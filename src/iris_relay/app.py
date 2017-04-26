# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.


import hmac
import re
from base64 import b64encode, decodestring, urlsafe_b64encode
from hashlib import sha1, sha512
from logging import basicConfig, getLogger
import logging
from urllib import unquote_plus, urlencode, unquote

from streql import equals
from twilio import twiml
from urllib3.exceptions import MaxRetryError
import yaml
import falcon
import ujson
import falcon.uri

from iris_relay.client import IrisClient
from iris_relay.gmail import Gmail

logger = getLogger(__name__)

uuid4hex = re.compile('[0-9a-f]{32}\Z', re.I)


def process_api_response(content):
    try:
        j = ujson.loads(content)
        if 'app_response' in j:
            return j['app_response']
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
        lst = [unquote_plus(kv.replace('=', ''))
               for kv in sorted(post_body.split('&'))]
        lst.insert(0, s)
        s = ''.join(lst)

    # compute signature and compare signatures
    if isinstance(s, str):
        mac = hmac.new(token, s, sha1)
    elif isinstance(s, unicode):
        mac = hmac.new(token, s.encode("utf-8"), sha1)
    else:
        # Should never happen
        raise TypeError
    computed = b64encode(mac.digest())
    if utf:
        computed = computed.decode('utf-8')

    return computed.strip()


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
        post_body = req.context['body']

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

        endpoint = self.config['iris']['hook']['gmail']
        data = body.get('message', {}).get('data')

        results = []
        mark_read_mids = set()
        for msg_id_gmail, headers, body in self.gmail.list_unread_message():
            data = ujson.dumps({'body': body, 'headers': headers})
            try:
                result = self.iclient.post(endpoint, data, raw=True)
            except MaxRetryError as ex:
                logger.error(ex.reason)
            else:
                # If status from Iris API == 204 or 400, mark message as read
                if result.status == 204 or result.status == 400:
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
        if all(r.status == 204 for r in results):
            resp.status = falcon.HTTP_204
            return
        elif any(r.status == 400 for r in results):
            # TODO(khrichar): reply with error to gmail sender
            raise falcon.HTTPBadRequest('Bad Request', '')
        else:
            # TODO(khrichar): reply with error to gmail sender
            raise falcon.HTTPInternalServerError('Internal Server Error', 'Unknown response from API')


class GmailOneClickRelay(object):

    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient
        self.data_keys = ('msg_id', 'email_address', 'cmd')  # Order here matters; needs to match what is in iris-api
        self.hmac = hmac.new(self.config['gmail_one_click_url_key'], '', sha512)

    def on_get(self, req, resp):
        token = req.get_param('token', True)
        data = {}
        for key in self.data_keys:
            data[key] = req.get_param(key, True)

        if not self.validate_token(token, data):
            raise falcon.HTTPForbidden('Invalid token for these given values', '')

        endpoint = self.config['iris']['hook']['gmail_one_click']

        try:
            result = self.iclient.post(endpoint, data)
        except MaxRetryError:
            logger.exception('Hitting iris-api failed for gmail oneclick')
        else:
            if result.status == 204:
                resp.status = falcon.HTTP_204
                return
            else:
                logger.error('Unexpected status code from api %s for gmail oneclick', result.status)

        raise falcon.HTTPInternalServerError('Internal Server Error', 'Invalid response from API')

    def validate_token(self, given_token, data):
        mac = self.hmac.copy()
        mac.update(' '.join(data[key] for key in self.data_keys))
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
        r = twiml.Response()
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
        loop = req.get_param('loop')

        if not message_id.isdigit() and not uuid4hex.match(message_id):
            raise falcon.HTTPBadRequest('Bad message id',
                                        'message id must be int/hex')

        action = self.get_api_url(req.env, 'v0', 'twilio/calls/relay?') + urlencode({
            'message_id': message_id,
        })

        r = twiml.Response()
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
        r = twiml.Response()
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

        # If we weren't given a message_id, this is an OOB message and there isn't
        # anything to say, so hang up.
        if not message_id:
            self.return_twixml_call('Thank you', resp)
            return

        if not message_id.isdigit() and not uuid4hex.match(message_id):
            raise falcon.HTTPBadRequest('Bad message id', 'message id must be int/hex')

        try:
            path = self.config['iris']['hook']['twilio_calls']
            re = self.iclient.post(path, req.context['body'], raw=True, params={
                'message_id': message_id
            })
        except MaxRetryError as e:
            logger.error(e.reason)
            self.return_twixml_call('Connection error to web hook.', resp)
            return

        if re.status is not 200:
            self.return_twixml_call(
                'Got status code: %d, content: %s' % (re.status,
                                                      re.data[0:100]), resp)
            return
        else:
            body = process_api_response(re.data)
            self.return_twixml_call(body, resp)
            return


class TwilioMessagesRelay(object):
    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient

    @staticmethod
    def return_twixml_message(reason, resp):
        r = twiml.Response()
        r.message(reason)
        resp.status = falcon.HTTP_200
        resp.body = str(r)
        resp.content_type = 'application/xml'

    def on_post(self, req, resp):
        """
        Accept twilio SMS webhook and forward to iris API
        """
        try:
            path = self.config['iris']['hook']['twilio_messages']
            re = self.iclient.post(path, req.context['body'], raw=True)
        except MaxRetryError as e:
            logger.error(e.reason)
            self.return_twixml_message('Connection error to web hook.', resp)
            return

        if re.status is not 200:
            self.return_twixml_message(
                'Got status code: %d, content: %s' % (re.status,
                                                      re.data[0:100]), resp)
            return
        else:
            body = process_api_response(re.data)
            self.return_twixml_message(body, resp)
            return


class TwilioDeliveryStatus(object):
    def __init__(self, config, iclient):
        self.iclient = iclient
        self.endpoint = config['iris']['hook']['twilio_status']

    def on_post(self, req, resp):
        """
        Accept twilio POST that has message delivery status, and pass it
        to iris-api
        """

        try:
            re = self.iclient.post(self.endpoint, req.context['body'], raw=True)
        except MaxRetryError:
            logger.exception('Failed posting data to iris-api')
            raise falcon.HTTPInternalServerError('Internal Server Error', 'API call failed')

        if re.status is not 204:
            logger.error('Invalid response from API for delivery status update: %s', re.status)
            raise falcon.HTTPBadRequest('Likely bad params passed', 'Invalid response from API')

        resp.status = falcon.HTTP_204


class SlackMessagesRelay(object):
    def __init__(self, config, iclient):
        self.config = config
        self.iclient = iclient
        self.verification_token = self.config['slack']['verification_token']

    def valid_token(self, token):
        return equals(self.verification_token, token)

    def return_slack_message(self, resp, text):
        resp.status = falcon.HTTP_200
        resp.content_type = 'application/json'
        resp.body = ujson.dumps({'text': text})

    def on_post(self, req, resp):
        """
        Accept slack's message from interactive buttons
        """
        try:
            form_post = falcon.uri.parse_query_string(req.context['body'])
            payload = ujson.loads(form_post['payload'])
            if not self.valid_token(payload['token']):
                logger.error('Invalid token sent in the request.')
                raise falcon.HTTPUnauthorized('Access denied',
                                              'Not a valid auth token')
            try:
                msg_id = int(payload['callback_id'])
            except KeyError as e:
                logger.error('callback_id not found in the json payload.')
                raise falcon.HTTPBadRequest('Bad Request', 'Callback id not found')
            except ValueError as e:
                logger.error('Callback ID not an integer: %s', payload['callback_id'])
                raise falcon.HTTPBadRequest('Bad Request', 'Callback id must be int')
            data = {'msg_id': msg_id,
                    'source': payload['user']['name'],
                    'content': payload['actions'][0]['name']}
            endpoint = self.config['iris']['hook']['slack']
            try:
                result = self.iclient.post(endpoint, data)
            except MaxRetryError as e:
                logger.error(e.reason)
                return
            if result.status == 400:
                raise falcon.HTTPBadRequest('Bad Request', '')
            elif result.status is not 200:
                raise falcon.HTTPInternalServerError('Internal Server Error', 'Unknown response from the api')
            else:
                content = process_api_response(result.data)
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
            logger.exception('Failed reading healthcheck file')
            raise falcon.HTTPNotFound()

        resp.status = falcon.HTTP_200
        resp.content_type = 'text/plain'
        resp.body = health


class GmailVerification(object):

    def __init__(self, vcode):
        self.msg = 'google-site-verification: %s' % vcode

    def on_get(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.body = self.msg


class AuthMiddleware(object):

    def __init__(self, config):
        self.config = config
        self.basic_auth = config['server']['basic_auth']
        token = config['twilio']['auth_token']
        if isinstance(token, list):
            self.twilio_auth_token = token
        else:
            self.twilio_auth_token = [token]
        if self.config['server'].get('debug'):
            self.auth = lambda x: True

    def process_request(self, req, resp):
        # http basic auth
        if self.config['server'].get('enable_basic_auth'):
            hdr_auth = req.get_header('AUTHORIZATION')
            if not hdr_auth:
                raise falcon.HTTPUnauthorized('Access denied', 'No auth header', [])

            auth = re.sub('^Basic ', '', hdr_auth)
            usr, pwd = decodestring(auth).split(':')
            if not equals(self.basic_auth.get(usr, ''), pwd):
                logger.warning('basic auth failure: %s', usr)
                raise falcon.HTTPUnauthorized('Access denied', 'Basic auth failure', [])

        segments = req.path.strip('/').split('/')
        if segments[0] == 'api':
            if len(segments) >= 3:
                # twilio validation
                if segments[2] == 'twilio':
                    sig = req.get_header('X_TWILIO_SIGNATURE')
                    if sig is None:
                        logger.warning("no twilio signature found!")
                        raise falcon.HTTPUnauthorized('Access denied', 'No Twilio signature', [])
                    uri = [req.protocol, '://',
                           req.get_header('HOST'),
                           self.config['server'].get('lb_routing_path', ''),
                           req.path]
                    if req.query_string:
                        uri.append('?')
                        uri.append(req.query_string)
                    post_body = req.context['body']
                    expected_sigs = [compute_signature(t, ''.join(uri), post_body)
                                     for t in self.twilio_auth_token]
                    if sig not in expected_sigs:
                        logger.warning('twilio validation failure: %s not in possible sigs: %s',
                                       sig, expected_sigs)
                        raise falcon.HTTPUnauthorized('Access denied', 'Twilio auth failure', [])
                    return
                elif segments[2] == 'gmail' or segments[2] == 'gmail-oneclick' or segments[2] == 'slack':
                    return
        elif len(segments) == 1:
            if segments[0] == 'health' or segments[0] == 'healthcheck':
                return
            elif segments[0] == self.config['gmail'].get('verification_code'):
                return

        raise falcon.HTTPUnauthorized('Access denied', 'Authentication failed', [])


class ReqBodyMiddleware(object):
    '''
    Falcon's req object has a stream that we read to obtain the post body. However, we can only read this once, and
    we often need the post body twice (once for Twilio signature validation and once to relay the message onto Iris
    API. To avoid this problem, we read the post body into the request context and access it from there.

    IMPORTANT NOTE: Because we use stream.read() here, all other uses of this method will return '', not the post body.
    '''

    def process_request(self, req, resp):
        req.context['body'] = req.stream.read()


def read_config_from_argv():
    import sys
    if len(sys.argv) < 2:
        print 'Usage: %s CONFIG_FILE' % sys.argv[0]
        sys.exit(1)

    with open(sys.argv[1], 'r') as config_file:
        return yaml.safe_load(config_file)


def get_relay_app(config=None):
    basicConfig(format='[%(asctime)s] [%(process)d] [%(levelname)s] %(name)s %(message)s',
                level=logging.INFO,
                datefmt='%Y-%m-%d %H:%M:%S %z')

    if not config:
        config = read_config_from_argv()

    iclient = IrisClient(config['iris']['host'],
                         config['iris']['port'],
                         config['iris'].get('relay_app_name', 'iris-relay'),
                         config['iris']['api_key'])
    gmail = Gmail(config.get('gmail'), config.get('proxy'))

    # Note that ReqBodyMiddleware must be run before AuthMiddleware, since
    # authentication uses the post body
    app = falcon.API(middleware=[ReqBodyMiddleware(), AuthMiddleware(config)])

    gmail_relay = GmailRelay(config, iclient, gmail)
    gmail_oneclick_relay = GmailOneClickRelay(config, iclient)
    twilio_calls_say = TwilioCallsSay()
    twilio_calls_gather = TwilioCallsGather(config)
    twilio_calls_relay = TwilioCallsRelay(config, iclient)
    twilio_messages_relay = TwilioMessagesRelay(config, iclient)
    slack_authenticate = SlackAuthenticate()
    slack_messages_relay = SlackMessagesRelay(config, iclient)
    twilio_delivery_status = TwilioDeliveryStatus(config, iclient)
    healthcheck = Healthcheck(config.get('healthcheck_path'))

    app.add_route('/api/v0/gmail/relay', gmail_relay)
    app.add_route('/api/v0/gmail-oneclick/relay', gmail_oneclick_relay)
    app.add_route('/api/v0/twilio/calls/say', twilio_calls_say)
    app.add_route('/api/v0/twilio/calls/gather', twilio_calls_gather)
    app.add_route('/api/v0/twilio/calls/relay', twilio_calls_relay)
    app.add_route('/api/v0/twilio/messages/relay', twilio_messages_relay)
    app.add_route('/api/v0/twilio/status', twilio_delivery_status)
    app.add_route('/api/v0/slack/authenticate', slack_authenticate)
    app.add_route('/api/v0/slack/messages/relay', slack_messages_relay)
    app.add_route('/healthcheck', healthcheck)
    if 'verification_code' in config['gmail']:
        vcode = config['gmail']['verification_code']
        app.add_route('/' + vcode, GmailVerification(vcode))

    return app


def get_relay_server():
    from gevent.pywsgi import WSGIServer
    config = read_config_from_argv()
    app = get_relay_app(config)
    server = config['server']
    print 'LISTENING: %(host)s:%(port)d' % server
    return WSGIServer((server['host'], server['port']), app)


if __name__ == '__main__':
    get_relay_server().serve_forever()
