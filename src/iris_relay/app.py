# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.

from gevent import monkey
monkey.patch_all()  # NOQA
import hmac
import time
import hashlib
import re
from base64 import b64encode, decodebytes, urlsafe_b64encode
from hashlib import sha1, sha512
from cryptography.fernet import Fernet
from logging import basicConfig, getLogger
from importlib import import_module
import logging
import uuid

from urllib.parse import unquote_plus, urlencode, unquote
import urllib.request as urllib2

from . import db
from twilio.twiml.voice_response import VoiceResponse
from twilio.twiml.messaging_response import MessagingResponse
from urllib3.exceptions import MaxRetryError
from requests.exceptions import ConnectionError
import yaml
import falcon
from falcon import (HTTP_200, HTTP_503)
import ujson
import falcon.uri
import os
from saml2 import entity
import base64

from iris_relay.gmail import Gmail
from iris_relay.saml import SAML

from iris_relay.client import IrisClient
from oncallclient import OncallClient

logger = getLogger(__name__)

MAX_SAML_SESSION_TTL = 900  # 15 minutes
MAX_LOGIN_SESSIONS = 20000


def process_api_response(content):
    try:
        if 'app_response' in content:
            return content['app_response']
    except ValueError:
        logger.exception('Failed parsing json from api')

    return 'Invalid response from API server: ' + content


def compute_signature(token, uri, post_body, utf=False):
    """Compute the signature for a given request
    :param uri: full URI that Twilio requested on your server
    :param post_body: post vars that Twilio sent with the request, list of str
    :param utf: whether return should be bytestring or unicode (python3)
    :returns: The computed signature
    """
    s = uri
    if len(post_body) > 0:
        p_b_split = post_body.decode().split('&')
        lst = [unquote_plus(kv.replace('=', ''))
               for kv in sorted(p_b_split)]
        lst.insert(0, s)
        s = ''.join(lst)

    s = s.encode('utf8')
    token = token.encode('utf8')

    # compute signature and compare signatures
    if isinstance(s, bytes):
        mac = hmac.new(token, s, sha1)
    else:
        # Should never happen
        raise TypeError
    computed = b64encode(mac.digest())
    if utf:
        computed = computed.decode('utf-8')

    return computed.strip()


def is_valid_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


class IDPInitiated(object):
    def __init__(self, config, saml_manager, saml_encryption=False):
        self.saml_manager = saml_manager
        self.access_ttl = config['access_ttl']
        self.refresh_ttl = config['refresh_ttl']
        self.redirect_url = config['redirect_url']
        self.username_attr = config.get('username_attr')
        key = config['encrypt_key']
        try:
            self.fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
        except Exception as e:
            raise ValueError("Invalid Fernet key provided") from e
        self.saml_encryption = saml_encryption

    def on_post(self, req, resp, idp_name):
        """
        Handle POST requests from the IdP containing a SAMLResponse and optional RelayState.

        This endpoint completes the SAML login process by validating the SAMLResponse,
        issuing a refresh token, and redirecting the user back to the mobile app.

        If RelayState is a base64-encoded JSON object containing a saml_session_id, the handler
        will attempt to fetch corresponding session data (client_key, device_id) from the
        saml_login_session table. If found, the refresh token payload is encrypted using the
        client-provided key and returned as a deep link to the app.

        If no session is found and encryption is required, the request is rejected with 401.
        If encryption is optional, the response falls back to legacy behavior: appending
        token details to the URL fragment.

        Parameters:
            req (falcon.Request): The incoming HTTP request, containing SAMLResponse and RelayState.
            resp (falcon.Response): The HTTP response object used to set redirect headers.
            idp_name (str): The identity provider name used to select SAML configuration.

        Response:
            - HTTP 302 Redirect to mobile app with either encrypted payload (?data=...)
            or legacy token fragment (#token=...).
            - HTTP 401 Unauthorized if request is unsolicited or session validation fails
            in encryption-required mode.
            - HTTP 400 Bad Request if RelayState is invalid or missing required fields.
        """
        saml_client = self.saml_manager.saml_client_for(idp_name)
        req.context['body'] = req.context['body'].decode('utf-8')
        form_data = falcon.uri.parse_query_string(req.context['body'])

        # Pysaml2 defaults to config-defined encryption keys, but must
        # be passed a truthy dict in outstanding_certs in order to
        # do so.
        outstanding = {1: 1}
        authn_response = saml_client.parse_authn_request_response(
            form_data['SAMLResponse'],
            entity.BINDING_HTTP_POST,
            outstanding_certs=outstanding)
        req_id = authn_response.in_response_to
        unsolicited = req_id is None
        if unsolicited:
            raise falcon.HTTPUnauthorized('Unsolicited request')

        subject = authn_response.get_subject()
        username = subject.text
        if self.username_attr:
            username = authn_response.ava[self.username_attr][0]

        # Generate the actual refresh token and expiration
        refresh_token = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        refresh_exp = time.time() + self.refresh_ttl

        # Parse RelayState as base64-encoded JSON, or fallback to legacy string
        raw_relay_state = form_data.get('RelayState')
        saml_session_id = None
        redirect_location = self.redirect_url

        try:
            decoded = base64.urlsafe_b64decode(raw_relay_state.encode('utf-8')).decode('utf-8')
            relay_state_data = ujson.loads(decoded)
            redirect_location = relay_state_data.get('location', redirect_location)
            saml_session_id = relay_state_data.get('saml_session_id')
        except Exception:
            if self.saml_encryption:
                logger.info('Failed to decode RelayState')
                raise falcon.HTTPBadRequest('Invalid RelayState for encrypted flow')
            # Fallback: RelayState is a legacy location string
            redirect_location = raw_relay_state or self.redirect_url

        # Look up session data if saml_session_id is provided
        session_data = None
        connection = db.connect()
        cursor = connection.cursor()
        try:

            if saml_session_id:
                # delete expired sessions
                cursor.execute('DELETE FROM saml_login_session WHERE created < UNIX_TIMESTAMP() - %s', (MAX_SAML_SESSION_TTL,))
                # Fetch and consume session
                cursor.execute('''
                    SELECT client_key, device_id
                    FROM saml_login_session
                    WHERE id = %s
                ''', (saml_session_id,))
                session_data = cursor.fetchone()

                if session_data:
                    # session is one time use, so delete it after fetching
                    cursor.execute('DELETE FROM saml_login_session WHERE id = %s', (saml_session_id,))
                elif self.saml_encryption:
                    raise falcon.HTTPUnauthorized('Session not found for RelayState')
            elif self.saml_encryption:
                raise falcon.HTTPUnauthorized('saml_session_id was not found in RelayState')

            # validate req_id
            self.validate_and_consume_saml_id(cursor, req_id)

            # Store the encrypted refresh token in DB
            encrypted_token = self.fernet.encrypt(refresh_token.encode('utf-8'))
            cursor.execute('''
                INSERT INTO refresh_token (user_id, `key`, expiration)
                VALUES (
                    (SELECT id FROM target
                    WHERE name = %s AND type_id = (SELECT id FROM target_type WHERE name = 'user')),
                    %s, %s
                )
            ''', (username, encrypted_token, refresh_exp))
            connection.commit()
            key_id = cursor.lastrowid
        finally:
            cursor.close()
            connection.close()

        # If we have session data, encrypt response with the client-provided key
        if session_data:
            client_key, device_id = session_data
            payload = {
                "token": refresh_token,
                "keyId": key_id,
                "expiry": refresh_exp,
                "username": username,
                "created": int(time.time()),
                "device_id": device_id
            }
            try:
                f = Fernet(client_key.encode('utf-8'))
            except Exception:
                raise falcon.HTTPInternalServerError('Invalid encryption key in session data')

            encrypted_payload = f.encrypt(ujson.dumps(payload).encode('utf-8')).decode('utf-8')
            redirect_location = f"{redirect_location}?data={encrypted_payload}"
        else:
            # Legacy behavior: redirect with raw token in URL fragment
            redirect_location = ''.join([
                redirect_location,
                '#token=', refresh_token,
                '&keyId=', str(key_id),
                '&expiry=', str(refresh_exp),
                '&username=', username
            ])

        resp.set_header('Location', redirect_location)
        resp.status = falcon.HTTP_302

    def validate_and_consume_saml_id(self, cursor, req_id):
        cursor.execute('DELETE FROM saml_id WHERE id = %s', (req_id,))
        if cursor.rowcount == 0:
            raise falcon.HTTPUnauthorized('Unknown or expired SAML request ID')


class TokenRefresh(object):

    def __init__(self, config):
        self.access_ttl = config['access_ttl']
        self.fernet = Fernet(config['encrypt_key'])

    def on_get(self, req, resp):
        # Username verified in auth middleware
        username = req.context['user']
        access_token = hashlib.sha256(os.urandom(32)).hexdigest()
        encrypted_token = self.fernet.encrypt(access_token.encode('utf8'))
        exp = time.time() + self.access_ttl

        connection = db.connect()
        cursor = connection.cursor()
        try:
            cursor.execute('''INSERT INTO `access_token` (`user_id`, `key`, `expiration`)
                              VALUES ((SELECT `id` FROM `target` WHERE `name` = %s AND `type_id` =
                                      (SELECT `id` FROM `target_type` WHERE `name` = 'user')),
                                      %s,
                                      %s)''',
                           (username, encrypted_token, exp))
            connection.commit()
            key_id = cursor.lastrowid
        finally:
            cursor.close()
            connection.close()

        resp.body = ujson.dumps({'token': access_token, 'key_id': key_id, 'expiry': exp})


class SPInitiated(object):
    def __init__(self, saml_manager):
        self.saml_manager = saml_manager

    def on_get(self, req, resp, idp_name):
        """
        Initiates a Service Provider (SP)-initiated SAML authentication flow.

        This endpoint is called when a user begins login from the application side.
        It prepares a SAML authentication request and issues a redirect to the
        Identity Provider's (IdP) login endpoint.

        It performs the following steps:
        - Generates a SAML AuthN request using the configured SAML client.
        - Cleans up old entries from the `saml_id` table based on a TTL.
        - Limits the number of in-flight SAML requests to avoid resource abuse.
        - Stores the request ID and timestamp in the `saml_id` table.
        - Redirects the user to the IdP login URL provided by the SAML client.

        Headers:
            - Cache-Control and Pragma headers are explicitly set to avoid
            caching of redirect responses, as recommended by SAML spec.

        Query Parameters:
            idp_name (str): The identity provider to use for login.

        Response:
            - HTTP 302 redirect to the IdP login page.
            - HTTP 429 if too many active login sessions are in flight.
        """

        saml_client = self.saml_manager.saml_client_for(idp_name)
        reqid, info = saml_client.prepare_for_authenticate()
        connection = db.connect()
        cursor = connection.cursor()
        try:
            cursor.execute('DELETE FROM saml_id WHERE timestamp < UNIX_TIMESTAMP() - %s', (MAX_SAML_SESSION_TTL,))
            cursor.execute('SELECT COUNT(*) FROM saml_id')
            if cursor.fetchone()[0] > MAX_LOGIN_SESSIONS:
                raise falcon.HTTPTooManyRequests('Too many active auth sessions')

            cursor.execute('INSERT INTO `saml_id` (`id`, `timestamp`) VALUES (%s, %s)',
                           (reqid, int(time.time())))
            connection.commit()
        finally:
            cursor.close()
            connection.close()

        redirect_url = None
        # Select the IdP URL to send the AuthN request to
        for key, value in info['headers']:
            if key == 'Location':
                redirect_url = value
        # NOTE:
        #   I realize I _technically_ don't need to set Cache-Control or Pragma:
        #     http://stackoverflow.com/a/5494469
        #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
        #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
        #   We set those headers here as a "belt and suspenders" approach,
        #   since enterprise environments don't always conform to RFCs
        resp.set_header('Cache-Control', 'no-cache, no-store')
        resp.set_header('Pragma', 'no-cache')
        resp.set_header('Location', redirect_url)
        resp.status = falcon.HTTP_302


class OncallCalendarRelay(object):
    def __init__(self, oncall_client, oncall_base_url):
        self.oncall_client = oncall_client
        self.base_url = oncall_base_url

    def on_get(self, req, resp, ical_key):
        """Access the oncall calendar identified by the key.

        The response is in ical format and this url is intended to be
        supplied to any calendar application that can subscribe to
        calendars from the internet.
        """
        try:
            path = self.base_url + '/api/v0/ical/' + ical_key
            if req.query_string:
                path += '?%s' % req.query_string
            result = self.oncall_client.get(path)
        except (MaxRetryError, ConnectionError):
            logger.exception('request failed with exception')
        else:
            if result.status_code == 200:
                resp.status = falcon.HTTP_200
                resp.content_type = result.headers['Content-Type']
                resp.body = result.content
                return
            elif 400 <= result.status_code <= 499:
                resp.status = falcon.HTTP_404
                return

        raise falcon.HTTPInternalServerError('Internal Server Error', 'Invalid response from API')


class SAMLInitiate(object):

    def on_post(self, req, resp):
        """
        Endpoint: POST /api/v0/saml/initiate

        Initiates a SAML login session by accepting a client-generated encryption key and a device identifier.
        Stores this data in the `saml_login_session` table along with a generated session ID and creation timestamp.

        The session ID is returned to the client and must be included within RelayState in the SAML login flow.

        Expected JSON request body:
        {
            "client_key": "<base64-encoded 256-bit symmetric key>",
            "device_id": "<unique identifier for this device or app install>"
        }

        Successful JSON response:
        {
            "saml_session_id": "<server-generated UUID to be used as RelayState>"
        }

        Errors:
        - Returns HTTP 400 if the request body is invalid or required fields are missing.
        """
        req.context['body'] = req.context['body'].decode('utf-8')
        data = ujson.loads(req.context['body'])

        client_key = data.get("client_key")
        device_id = data.get("device_id")
        if not client_key or not device_id:
            raise falcon.HTTPBadRequest("Missing client_key or device_id")

        try:
            Fernet(client_key.encode('utf-8'))
        except Exception:
            raise falcon.HTTPBadRequest('Invalid client_key format')

        connection = db.connect()
        cursor = connection.cursor()
        try:
            # delete expired sessions
            cursor.execute('DELETE FROM saml_login_session WHERE created < UNIX_TIMESTAMP() - %s', (MAX_SAML_SESSION_TTL,))
            cursor.execute('SELECT COUNT(*) FROM saml_login_session')
            session_count = cursor.fetchone()[0]
            # prevent db from getting flooded if there were malicious requests
            if session_count >= MAX_LOGIN_SESSIONS:
                raise falcon.HTTPTooManyRequests('Too many active login sessions')

            saml_session_id = str(uuid.uuid4())
            cursor.execute(
                '''
                INSERT INTO saml_login_session (id, client_key, device_id, created)
                VALUES (%s, %s, %s, UNIX_TIMESTAMP())
                ''',
                (saml_session_id, client_key, device_id)
            )
            connection.commit()
        finally:
            cursor.close()
            connection.close()

        resp.body = ujson.dumps({"saml_session_id": saml_session_id})
        resp.status = falcon.HTTP_200
        resp.content_type = 'application/json'


class GmailRelay(object):
    def __init__(self, config, iclient, gmail):
        self.config = config
        self.iclient = iclient
        self.gmail = gmail

    def on_post(self, req, resp):
        """
        Accept Gmail push notification and forward to Iris API
        Listen for Gmail push notification, then fetch new emails and forward them to Iris API:

            1. Verify token
            2. Verify subscribed topic
            3. Fetch all unread emails from Gmail API, for each email:
                a. Forward to Iris API
                b. Modify email labels according to Iris API's response
            4. Return 204 to Gmail API if no error is returned from Iris API

        NOTE: We are not using the base64 data from pushed JSON, only subscription key is checked.
        The notification is only treated as a signal for checking unread emails.

        Sample push notification from google:

            POST /api/v0/gmail/relay?token=fooooooooooooooooooooooooooooooo
            Content-type: application/json

            {
                "message": {
                    "data": "base64-no-line-feeds-variant-representation-of-payload",
                    "message_id": "string-value"
                },
                "subscription": "string-value"
            }

        Query string:
            token: statically configured in app config and only used for authentication.

        Refs:
            https://developers.google.com/gmail/api/guides/push
            https://cloud.google.com/pubsub/subscriber
        """
        config = self.config.get('gmail', {})
        token = req.get_param('token')
        post_body = req.context['body'].decode('utf-8')

        # Verify the request came from Google.
        if token != config.get('token'):
            raise falcon.HTTPUnauthorized('Unauthorized', 'Bad token', [])
        try:
            body = ujson.loads(unquote(post_body).rstrip('='))
        except Exception:
            logger.error("Failed to decode json from gmail push: %s", post_body)
            raise falcon.HTTPBadRequest('Bad Request', 'Json decode failed')

        # Verify the request is from the configured subscription.
        if body.get('subscription') != 'projects/{0}/subscriptions/{1}'.format(
                config.get('project'),
                config.get('subscription')
        ):
            raise falcon.HTTPBadRequest('Bad Request', 'Incorrect subscription')

        gmail_endpoint = self.config['iris']['host'] + '/v0/' + self.config['iris']['hook']['gmail']
        data = body.get('message', {}).get('data')

        results = []
        mark_read_mids = set()
        for msg_id_gmail, headers, body in self.gmail.list_unread_message():
            data = ujson.dumps({'body': body, 'headers': headers})
            try:
                result = self.iclient.post(gmail_endpoint, data=data)
            except (MaxRetryError, ConnectionError):
                logger.exception('request failed with exception')
            else:
                # If status from Iris API == 204 or 400, mark message as read
                if result.status_code == 204 or result.status_code == 400:
                    logger.info('Will mark gmail message %s as read', msg_id_gmail)
                    mark_read_mids.add(msg_id_gmail)
                results.append(result)
        if mark_read_mids:
            self.gmail.batch_mark_read(mark_read_mids)
        # FIXME: send metrics for number of messages pushed from gmail
        if len(results) == 0:
            user_id, history_id = self.gmail.parse_gmail_push_data(data)
            logger.warning('Got no message change history from Gmail: %s, %s',
                           user_id, history_id)
        # TODO(khrichar): need to be resilient to unauthorized message id's
        if all(r.status_code == 204 for r in results):
            resp.status = falcon.HTTP_204
            return
        elif any(r.status_code == 400 for r in results):
            # TODO(khrichar): reply with error to gmail sender
            raise falcon.HTTPBadRequest('Bad Request', '')
        else:
            # TODO(khrichar): reply with error to gmail sender
            raise falcon.HTTPInternalServerError(
                'Internal Server Error', 'Unknown response from API')


class GmailOneClickRelay(object):

    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient
        self.data_keys = ('msg_id', 'email_address', 'cmd')  # Order here matters; needs to match what is in iris-api
        key = self.config['gmail_one_click_url_key']
        key = key.encode('utf8')
        self.hmac = hmac.new(key, b'', sha512)

    def on_get(self, req, resp):
        token = req.get_param('token', True)
        data = {}
        for key in self.data_keys:
            data[key] = req.get_param(key, True)

        if not self.validate_token(token, data):
            raise falcon.HTTPForbidden('Invalid token for these given values', '')

        endpoint = self.config['iris']['host'] + '/v0/' + self.config['iris']['hook']['gmail_one_click']

        try:
            result = self.iclient.post(endpoint, data)
        except (MaxRetryError, ConnectionError):
            logger.exception('Hitting iris-api failed for gmail oneclick')
        else:
            if result.status_code == 204:
                resp.status = falcon.HTTP_204
                return
            else:
                logger.error('Unexpected status code from api %s for gmail oneclick', result.status_code)

        raise falcon.HTTPInternalServerError('Internal Server Error', 'Invalid response from API')

    def validate_token(self, given_token, data):
        mac = self.hmac.copy()
        text = ' '.join(data[key] for key in self.data_keys)
        text = text.encode('utf8')
        mac.update(text)
        return given_token == urlsafe_b64encode(mac.digest())


class TwilioCallsSay(object):

    def on_get(self, req, resp):
        """
        Echo back user provided content query string in TwiML:

        Example:
            Query strings:

            content: OK

            TwiML:

            <?xml version="1.0" encoding="UTF-8"?>
            <Response>
                <Say language="en-US" voice="alice">OK</Say>
            </Response>
        """
        content = req.get_param('content')
        loop = req.get_param('loop')
        r = VoiceResponse()
        r.say(content, voice='alice', loop=loop, language="en-US")
        resp.status = falcon.HTTP_200
        resp.body = str(r)
        resp.content_type = 'application/xml'

    def on_post(self, req, resp):
        self.on_get(req, resp)


class TwilioCallsGather(object):
    def __init__(self, config):
        self.config = config

    def get_api_url(self, env, v, path):
        name = ''.join([env['wsgi.url_scheme'], '://',
                        env['HTTP_HOST'],
                        self.config['server'].get('lb_routing_path', '')])
        return '/'.join([name, 'api', v, path])

    def on_post(self, req, resp):
        """
        Echo gather instruction in TwiML:

        Example:
            Query strings:

            content: Your alert has been fired.
            instruction: Press 1 to claim alert.
            message_id: 123


            TwiML:

            <?xml version="1.0" ?>
            <Response>
                <Pause length="2"/>
                <Say language="en-US" voice="alice">Press pound for menu.</Say>
                <Gather timeout="0" finishOnKey="#">
                    <Say language="en-US" voice="alice">Your alert has been fired.</Say>
                </Gather>
                <Gather action="http://$endpoint_domain/iris/api/v0/twilio/calls/relay?message_id=123" numDigits="1">
                    <Say language="en-US" voice="alice">Press 1 to claim alert.</Say>
                </Gather>
            </Response>
        """
        content = req.get_param('content', required=True)
        instruction = req.get_param('instruction', required=True)
        message_id = req.get_param('message_id', required=True)
        incident_id = req.get_param('incident_id')
        target = req.get_param('target')
        loop = req.get_param('loop')

        if not message_id.isdigit() and not is_valid_uuid(message_id):
            raise falcon.HTTPBadRequest('Bad message id',
                                        'message id must be int/hex')

        action = self.get_api_url(req.env, 'v0', 'twilio/calls/relay?') + urlencode({
            'message_id': message_id,
            'incident_id': incident_id,
            'target': target
        })

        r = VoiceResponse()
        if req.get_param('AnsweredBy') == 'machine':
            logger.info("Voice mail detected for message id: %s", message_id)
            r.say(content, voice='alice', language="en-US", loop=loop)
        else:
            r.pause(length=2)
            r.say('Press pound for menu.', voice='alice', language="en-US")

            with r.gather(timeout=0, finishOnKey="#") as g:
                g.say(content, voice='alice', language="en-US")

            with r.gather(numDigits=1, action=action) as g:
                g.say(instruction, voice='alice', loop=loop, language="en-US")

        resp.status = falcon.HTTP_200
        resp.body = str(r)
        resp.content_type = 'application/xml'


class TwilioCallsRelay(object):
    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient

    @staticmethod
    def return_twixml_call(reason, resp):
        r = VoiceResponse()
        r.say(reason, voice='alice', loop=2, language="en-US")
        r.hangup()
        resp.status = falcon.HTTP_200
        resp.body = str(r)
        resp.content_type = 'application/xml'

    def on_post(self, req, resp):
        """
        Accept twilio gather callbacks and forward to iris API
        """
        message_id = req.get_param('message_id')
        incident_id = req.get_param('incident_id')
        target = req.get_param('target')

        # If we weren't given a message_id, this is an OOB message and there isn't
        # anything to say, so hang up.
        if not message_id:
            self.return_twixml_call('Thank you', resp)
            return

        if not message_id.isdigit() and not is_valid_uuid(message_id):
            raise falcon.HTTPBadRequest('Bad message id', 'message id must be int/hex')

        try:
            path = self.config['iris']['host'] + '/v0/' + self.config['iris']['hook']['twilio_calls']
            re = self.iclient.post(path, data=req.context['body'].decode('utf-8'), params={
                'message_id': message_id,
                'incident_id': incident_id,
                'target': target
            })
        except (MaxRetryError, ConnectionError):
            logger.exception('request failed with exception')
            self.return_twixml_call('Connection error to web hook.', resp)
            return

        if re.status_code != 200:
            self.return_twixml_call(
                'Got status code: %d, content: %s' % (re.status_code,
                                                      re.text[0:100]), resp)
            return
        else:
            body = process_api_response(re.json())
            self.return_twixml_call(body, resp)
            return


class TwilioMessagesRelay(object):
    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient

    @staticmethod
    def return_twixml_message(reason, resp):
        r = MessagingResponse()
        r.message(reason)
        resp.status = falcon.HTTP_200
        resp.body = str(r)
        resp.content_type = 'application/xml'

    def on_post(self, req, resp):
        """
        Accept twilio SMS webhook and forward to iris API
        """
        try:
            path = self.config['iris']['host'] + '/v0/' + self.config['iris']['hook']['twilio_messages']
            re = self.iclient.post(path, data=req.context['body'].decode('utf-8'))
        except (MaxRetryError, ConnectionError):
            logger.exception('request failed with exception')
            self.return_twixml_message('Connection error to web hook.', resp)
            return

        if re.status_code != 200:
            self.return_twixml_message(
                'Got status code: %d, content: %s' % (re.status_code,
                                                      re.text[0:100]), resp)
            return
        else:
            body = process_api_response(re.json())
            self.return_twixml_message(body, resp)
            return


class TwilioDeliveryStatus(object):
    def __init__(self, config, iclient):
        self.iclient = iclient
        self.endpoint = config['iris']['host'] + '/v0/' + config['iris']['hook']['twilio_status']

    def on_post(self, req, resp):
        """
        Accept twilio POST that has message delivery status, and pass it
        to iris-api
        """

        try:
            re = self.iclient.post(self.endpoint, data=req.context['body'].decode('utf-8'))
        except (MaxRetryError, ConnectionError):
            logger.exception('Failed posting data to iris-api')
            raise falcon.HTTPInternalServerError('Internal Server Error', 'API call failed')

        if re.status_code != 204:
            logger.error('Invalid response from API for delivery status update: %s', re.status_code)
            raise falcon.HTTPBadRequest('Likely bad params passed', 'Invalid response from API')

        resp.status = falcon.HTTP_204


class SlackMessagesRelay(object):
    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient
        self.verification_token = self.config['slack']['verification_token']

    def valid_token(self, token):
        return self.verification_token == token

    def return_slack_message(self, resp, text):
        resp.status = falcon.HTTP_200
        resp.content_type = 'application/json'
        resp.body = ujson.dumps({'text': text,
                                 'replace_original': False})

    def on_post(self, req, resp):
        """
        Accept slack's message from interactive buttons
        """
        try:
            req.context['body'] = req.context['body'].decode('utf-8')
            form_post = falcon.uri.parse_query_string(req.context['body'])
            payload = ujson.loads(form_post['payload'])
            if not self.valid_token(payload['token']):
                logger.error('Invalid token sent in the request.')
                raise falcon.HTTPUnauthorized('Access denied',
                                              'Not a valid auth token')
            try:
                callback_id = int(payload['callback_id'])
            except KeyError as e:
                logger.error(e)
                logger.error('callback_id not found in the json payload.')
                raise falcon.HTTPBadRequest('Bad Request', 'Callback id not found')
            except ValueError as e:
                logger.error(e)
                logger.error('Callback ID not an integer: %s', payload['callback_id'])
                raise falcon.HTTPBadRequest('Bad Request', 'Callback id must be int')
            data = {'msg_id': callback_id,
                    'callback_id': callback_id,
                    'source': payload['user']['name'],
                    'content': payload['actions'][0]['name']}
            endpoint = self.config['iris']['host'] + '/v0/' + self.config['iris']['hook']['slack']
            try:
                result = self.iclient.post(endpoint, ujson.dumps(data))
            except (MaxRetryError, ConnectionError):
                logger.exception('request failed with exception')
                return
            if result.status_code == 400:
                raise falcon.HTTPBadRequest('Bad Request', '')
            elif result.status_code != 200:
                raise falcon.HTTPInternalServerError('Internal Server Error', 'Unknown response from the api')
            else:
                content = process_api_response(result.json())
                self.return_slack_message(resp, content)
            return
        except Exception:
            logger.exception('Unable to read payload from slack. Our post body: %s', req.context['body'])
            raise falcon.HTTPBadRequest('Bad Request', 'Unable to read the payload from slack')


class SlackAuthenticate(object):
    """
    Will be used only once to setup slack OAuth
    """

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = 'Message Received'


class Healthcheck(object):
    def __init__(self, path):
        self.healthcheck_path = path

    def on_get(self, req, resp):
        if not self.healthcheck_path:
            logger.error('Healthcheck path not set')
            raise falcon.HTTPNotFound()

        try:
            with open(self.healthcheck_path) as f:
                health = f.readline().strip()
        except IOError:
            raise falcon.HTTPNotFound()

        try:
            connection = db.connect()
            cursor = connection.cursor()
            cursor.execute('SELECT version()')
            cursor.close()
            connection.close()
        except Exception:
            resp.status = HTTP_503
            resp.content_type = 'text/plain'
            resp.body = 'Could not connect to database'
        else:
            resp.status = HTTP_200
            resp.content_type = 'text/plain'
            resp.body = health


class GmailVerification(object):

    def __init__(self, vcode):
        self.msg = 'google-site-verification: %s' % vcode

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = self.msg


class IrisMobileSink(object):

    def __init__(self, iris_client, base_url):
        self.iris_client = iris_client
        self.base_url = base_url

    def __call__(self, req, resp):
        path = self.base_url + '/v0/' + '/'.join(req.path.split('/')[4:])
        if req.query_string:
            path += '?%s' % req.query_string
        try:
            if req.method == 'POST':
                result = self.iris_client.post(path, data=req.context['body'].decode('utf-8'))
            elif req.method == 'GET':
                result = self.iris_client.get(path)
            elif req.method == 'OPTIONS':
                return
            else:
                raise falcon.HTTPMethodNotAllowed(['GET', 'POST', 'PUT', 'DELETE'])
        except (MaxRetryError, ConnectionError):
            logger.exception('request failed with exception')
            raise falcon.HTTPInternalServerError('Internal Server Error', 'Max retry error, api unavailable')
        if result.status_code == 400:
            raise falcon.HTTPBadRequest('Bad Request', '')
        elif str(result.status_code)[0] != '2':
            raise falcon.HTTPInternalServerError('Internal Server Error', 'Unknown response from the api')
        else:
            resp.status = falcon.HTTP_200
            resp.content_type = result.headers['Content-Type']
            resp.body = result.content


class OncallMobileSink(object):

    def __init__(self, oncall_client, base_url):
        self.oncall_client = oncall_client
        self.base_url = base_url

    def __call__(self, req, resp):
        path = self.base_url + '/api/v0/' + '/'.join(req.path.split('/')[4:])
        if req.query_string:
            path += '?%s' % req.query_string
        try:
            if req.method == 'GET':
                result = self.oncall_client.get(path)
            elif req.method == 'OPTIONS':
                return
            else:
                raise falcon.HTTPMethodNotAllowed(['GET', 'OPTIONS'])
        except (MaxRetryError, ConnectionError):
            logger.exception('request failed with exception')
            raise falcon.HTTPInternalServerError('Internal Server Error', 'Max retry error, api unavailable')
        if result.status_code == 400:
            raise falcon.HTTPBadRequest('Bad Request', '')
        elif str(result.status_code)[0] != '2':
            raise falcon.HTTPInternalServerError('Internal Server Error', 'Unknown response from the api')
        else:
            resp.status = falcon.HTTP_200
            resp.content_type = result.headers['Content-Type']
            resp.body = result.content


class RegisterDevice(object):

    def __init__(self, iris_client, base_url):
        self.iris = iris_client
        self.base_url = base_url

    def on_post(self, req, resp):
        data = ujson.loads(req.context['body'].decode('utf-8'))
        data['username'] = req.context['user']
        path = self.base_url + '/v0/devices'
        result = self.iris.post(path, ujson.dumps(data))
        if result.status_code == 400:
            raise falcon.HTTPBadRequest('Bad Request', '')
        elif result.status_code != 201:
            logger.error('Unknown response from API: %s: %s', result.status_code, result.content)
            raise falcon.HTTPInternalServerError('Internal Server Error', 'Unknown response from the api')
        resp.status = falcon.HTTP_201


class AuthMiddleware(object):

    def __init__(self, config):
        self.config = config
        self.basic_auth = config['server']['basic_auth']
        self.special_auth_endpoint_list = config['special_auth_endpoint_list']

        mobile_cfg = config.get('iris-mobile', {})
        self.mobile = mobile_cfg.get('activated', False)
        if self.mobile:
            mobile_auth = mobile_cfg['auth']
            self.time_window = mobile_auth.get('time_window', 60)
            self.fernet = Fernet(mobile_auth['encrypt_key'])
        else:
            self.time_window = None
            self.fernet = None

        token = config['twilio']['auth_token']
        if isinstance(token, list):
            self.twilio_auth_token = token
        else:
            self.twilio_auth_token = [token]
        self.debug = False
        if self.config['server'].get('debug'):
            self.debug = True

    def process_request(self, req, resp):
        if self.debug:
            return
        # CORS Pre-flight
        if req.method == 'OPTIONS':
            resp.status = falcon.HTTP_204
            return
        # http basic auth
        if self.config['server'].get('enable_basic_auth'):
            hdr_auth = req.get_header('AUTHORIZATION')
            if not hdr_auth:
                raise falcon.HTTPUnauthorized('Access denied', 'No auth header', [])

            auth = re.sub('^Basic ', '', hdr_auth)
            usr, pwd = decodebytes(auth).split(':')
            if not self.basic_auth.get(usr, '') == pwd:
                logger.warning('basic auth failure: %s', usr)
                raise falcon.HTTPUnauthorized('Access denied', 'Basic auth failure', [])

        segments = req.path.strip('/').split('/')
        if segments[0] == 'api':
            if len(segments) >= 3:
                # the auth_postprocessing_list is for auths which should be handled separately by the function handling the corresponding endpoint
                if self.special_auth_endpoint_list and segments[2] in self.special_auth_endpoint_list:
                    return
                # twilio validation
                if segments[2] == 'twilio':
                    sig = req.get_header('X_TWILIO_SIGNATURE')
                    if sig is None:
                        logger.warning("no twilio signature found!")
                        raise falcon.HTTPUnauthorized('Access denied', 'No Twilio signature', [])
                    protocol = (req.scheme if req.scheme else 'https')
                    uri = [protocol, '://',
                           req.get_header('HOST'),
                           self.config['server'].get('lb_routing_path', ''),
                           req.path]
                    if req.query_string:
                        uri.append('?')
                        uri.append(req.query_string)
                    post_body = req.context['body']
                    expected_sigs = [compute_signature(t, ''.join(uri), post_body)
                                     for t in self.twilio_auth_token]
                    sig = sig.encode('utf8')
                    if sig not in expected_sigs:
                        logger.warning('twilio validation failure: %s not in possible sigs: %s',
                                       sig, expected_sigs)
                        raise falcon.HTTPUnauthorized('Access denied', 'Twilio auth failure', [])
                    return
                elif self.mobile and (segments[2] == 'mobile' or segments[2] == 'oncall'):
                    # Only allow refresh tokens for /refresh, only access for all else
                    table = 'refresh_token' if segments[3] == 'refresh' else 'access_token'
                    key_query = '''SELECT `key`, `target`.`name`
                                   FROM `%s` JOIN `target` ON `user_id` = `target`.`id`
                                   WHERE `%s`.`id` = %%s
                                   AND `expiration` > %%s''' % (table, table)
                    method = req.method
                    auth = req.get_header('Authorization', required=True)

                    items = urllib2.parse_http_list(auth)
                    parts = urllib2.parse_keqv_list(items)

                    if 'signature' not in parts or 'keyId' not in parts or 'timestamp' not in parts:
                        raise falcon.HTTPUnauthorized('Authentication failure: invalid header')

                    try:
                        window = int(parts['timestamp'])
                        time_diff = abs(time.time() - window)
                    except ValueError:
                        raise falcon.HTTPUnauthorized('Authentication failure: invalid header')
                    client_digest = parts['signature']
                    key_id = parts['keyId']
                    body = req.context['body'].decode('utf8')
                    path = req.env['PATH_INFO']
                    qs = req.env['QUERY_STRING']
                    if qs:
                        path = path + '?' + qs
                    text = '%s %s %s %s' % (window, method, path, body)
                    text = text.encode('utf8')

                    conn = db.connect()
                    cursor = conn.cursor()
                    cursor.execute(key_query, (key_id, time.time()))
                    row = cursor.fetchone()
                    conn.close()
                    # make sure that there exists a row for the corresponding username
                    if row is None:
                        raise falcon.HTTPUnauthorized('Authentication failure: server')
                    key = self.fernet.decrypt(str(row[0]).encode('utf8'))
                    key = key
                    req.context['user'] = row[1]

                    HMAC = hmac.new(key, text, hashlib.sha512)
                    digest = urlsafe_b64encode(HMAC.digest())

                    if hmac.compare_digest(client_digest.encode('utf8'), digest) and time_diff < self.time_window:
                        return
                    else:
                        raise falcon.HTTPUnauthorized('Authentication failure: server')
                elif segments[2] == 'gmail' or segments[2] == 'gmail-oneclick' or segments[2] == 'slack' or segments[2] == 'ical':
                    return
        elif len(segments) == 1:
            if segments[0] == 'health' or segments[0] == 'healthcheck':
                return
            elif segments[0] == self.config.get('gmail', {}).get('verification_code'):
                return

        elif segments[0] == 'saml':
            return
        raise falcon.HTTPUnauthorized('Access denied', 'Authentication failed', [])


class ReqBodyMiddleware(object):
    '''
    Falcon's req object has a stream that we read to obtain the post body. However, we can only read this once, and
    we often need the post body twice (once for Twilio signature validation and once to relay the message onto Iris
    API. To avoid this problem, we read the post body into the request context and access it from there.

    IMPORTANT NOTE: Because we use bounded_stream.read() here, all other uses of this method will return '', not the post body.
    '''

    def process_request(self, req, resp):
        req.context['body'] = req.bounded_stream.read()


class CORS(object):
    # Based on example from kgriffs
    def __init__(self, allowed_origins):
        self.allowed_origins = allowed_origins

    def process_response(self, req, resp, resource, req_succeeded):
        origin = req.get_header('origin')
        if not origin:
            return
        if origin in self.allowed_origins:
            resp.set_header('Access-Control-Allow-Origin', origin)
        else:
            return

        if (req_succeeded and req.method == 'OPTIONS' and req.get_header('Access-Control-Request-Method')):
            # This is a CORS preflight request. Patch the response accordingly.

            allow = resp.get_header('Allow')

            allow_headers = req.get_header(
                'Access-Control-Request-Headers'
            )
            if not allow_headers:
                allow_headers = '*'
            if not allow:
                allow = ''

            resp.set_headers((
                ('Access-Control-Allow-Methods', allow),
                ('Access-Control-Allow-Headers', allow_headers),
                ('Access-Control-Max-Age', '86400'),  # 24 hours
            ))


def read_config_from_argv():
    import sys
    if len(sys.argv) < 2:
        print(('Usage: %s CONFIG_FILE' % sys.argv[0]))
        sys.exit(1)

    with open(sys.argv[1], 'r') as config_file:
        return yaml.safe_load(config_file)


def get_relay_app(config=None):
    basicConfig(format='[%(asctime)s] [%(process)d] [%(levelname)s] %(name)s %(message)s',
                level=logging.INFO,
                datefmt='%Y-%m-%d %H:%M:%S %z')

    if not config:
        config = read_config_from_argv()

    oncall_client = OncallClient(app=config['oncall'].get('relay_app_name', 'iris-relay'),
                                 key=config['oncall']['api_key'],
                                 api_host=config['oncall']['url'])

    iclient = IrisClient(app=config['iris'].get('relay_app_name', 'iris-relay'),
                                              api_host=config['iris']['host'],
                                              key=config['iris']['api_key'])

    saml = SAML(config.get('saml'))
    saml_encryption = config.get('saml_encryption', False)

    # Note that ReqBodyMiddleware must be run before AuthMiddleware, since
    # authentication uses the post body
    app = None
    if config.get('permissive_cors'):
        app = falcon.App(cors_enable=True, middleware=[ReqBodyMiddleware(), AuthMiddleware(config)])
    else:
        cors = CORS(config.get('allow_origins_list', []))
        app = falcon.App(middleware=[ReqBodyMiddleware(), AuthMiddleware(config), cors])
    app.req_options.strip_url_path_trailing_slash = True

    ical_relay = OncallCalendarRelay(oncall_client, config['oncall']['url'])
    app.add_route('/api/v0/ical/{ical_key}', ical_relay)

    gmail_config = config.get('gmail')
    if gmail_config:
        gmail = Gmail(gmail_config, config.get('proxy'))
        gmail_relay = GmailRelay(config, iclient, gmail)
        gmail_oneclick_relay = GmailOneClickRelay(config, iclient)
        app.add_route('/api/v0/gmail/relay', gmail_relay)
        app.add_route('/api/v0/gmail-oneclick/relay', gmail_oneclick_relay)
        if 'verification_code' in gmail_config:
            vcode = config['gmail']['verification_code']
            app.add_route('/' + vcode, GmailVerification(vcode))

    twilio_calls_say = TwilioCallsSay()
    twilio_calls_gather = TwilioCallsGather(config)
    twilio_calls_relay = TwilioCallsRelay(config, iclient)
    twilio_messages_relay = TwilioMessagesRelay(config, iclient)
    slack_authenticate = SlackAuthenticate()
    slack_messages_relay = SlackMessagesRelay(config, iclient)
    twilio_delivery_status = TwilioDeliveryStatus(config, iclient)
    healthcheck = Healthcheck(config.get('healthcheck_path'))

    app.add_route('/api/v0/twilio/calls/say', twilio_calls_say)
    app.add_route('/api/v0/twilio/calls/gather', twilio_calls_gather)
    app.add_route('/api/v0/twilio/calls/relay', twilio_calls_relay)
    app.add_route('/api/v0/twilio/messages/relay', twilio_messages_relay)
    app.add_route('/api/v0/twilio/status', twilio_delivery_status)
    app.add_route('/api/v0/slack/authenticate', slack_authenticate)
    app.add_route('/api/v0/slack/messages/relay', slack_messages_relay)
    app.add_route('/healthcheck', healthcheck)
    mobile_cfg = config.get('iris-mobile', {})
    if mobile_cfg.get('activated'):
        db.init(config['db'])
        mobile_iris_client = IrisClient(app=mobile_cfg.get('relay_app_name', 'iris-relay'),
                                              api_host=mobile_cfg['host'],
                                              key=mobile_cfg['api_key'])

        mobile_oncall_client = OncallClient(
            app=mobile_cfg.get('relay_app_name', 'iris-relay'),
            key=mobile_cfg['oncall']['api_key'],
            api_host=mobile_cfg['oncall']['url'])

        iris_mobile_sink = IrisMobileSink(mobile_iris_client, mobile_cfg['host'])
        oncall_mobile_sink = OncallMobileSink(mobile_oncall_client, mobile_cfg['oncall']['url'])
        app.add_sink(oncall_mobile_sink, prefix='/api/v0/oncall/')
        app.add_sink(iris_mobile_sink, prefix='/api/v0/mobile/')
        app.add_route('/saml/login/{idp_name}', SPInitiated(saml))
        app.add_route('/saml/sso/{idp_name}', IDPInitiated(mobile_cfg.get('auth'), saml, saml_encryption=saml_encryption))
        app.add_route('/saml/initiate', SAMLInitiate())
        app.add_route('/api/v0/mobile/refresh', TokenRefresh(mobile_cfg.get('auth')))
        app.add_route('/api/v0/mobile/device', RegisterDevice(iclient, mobile_cfg['host']))

    for hook in config.get('post_init_hook', []):
        try:
            logger.debug('loading post init hook <%s>', hook)
            getattr(import_module(hook), 'init')(app, config)
        except Exception:
            logger.exception('Failed loading post init hook <%s>', hook)

    return app


def get_relay_server():
    from gevent.pywsgi import WSGIServer
    config = read_config_from_argv()
    app = get_relay_app(config)
    server = config['server']
    print(('LISTENING: %(host)s:%(port)d' % server))
    return WSGIServer((server['host'], server['port']), app)


if __name__ == '__main__':
    get_relay_server().serve_forever()
