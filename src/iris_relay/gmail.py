# -*- coding: utf-8 -*-

# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.

# pylint: disable=abstract-class-not-used, star-args
# from ast import literal_eval
from base64 import urlsafe_b64decode
from email import message_from_string
from logging import getLogger
from os import makedirs
from os.path import exists, join

from googleapiclient import errors
from googleapiclient.discovery import build
# from googleapiclient.http import BatchHttpRequest
from json import loads
from httplib2 import Http, ProxyInfo, socks
from oauth2client.file import Storage
from oauth2client import client, tools
# TODO(khrichar): figure out why keyring fails on OS X
# from oauth2client.keyring_storage import Storage

logger = getLogger(__name__)


email_headers_to_ignore = frozenset([('X-Autoreply', 'yes'),
                                     ('Auto-Submitted', 'auto-replied'),
                                     ('Precedence', 'bulk')])


def is_pointless_messages(message):
    payload = message.get('payload')
    if not payload:
        logger.warning('Payload not found in %s', message)
        return False
    for header in payload.get('headers', []):
        key = (header.get('name'), header.get('value'))
        if key in email_headers_to_ignore:
            logger.warning('Filtering out message %s due to header combination %s: %s', message, *key)
            return True
    return False


def process_message(message):
    """Process message to yield body and sender.

    :param message:
    :return: message body and sender
    :rtype: tuple(str, str)
    """
    payload = message.get('payload', {})
    headers = payload.get('headers', [])
    if 'data' in payload.get('body', {}):
        parts = [payload]
    else:
        parts = payload.get('parts', [])

    for part in parts:
        # TODO(khrichar): support other content types
        mime_type = part.get('mimeType')
        if mime_type == 'text/plain':
            encoded_content = part.get('body', {}).get('data', '')
            content = urlsafe_b64decode(encoded_content)
            yield headers, content
        elif mime_type == 'text/html':
            logger.debug('ignore html mime type for message: %s', message)
        elif mime_type == 'multipart/alternative':
            fake_message = {
                'payload': {
                    'parts': part.get('parts', []),
                    'headers': part.get('headers', {}),
                }
            }
            for h, c in process_message(fake_message):
                yield h, c
        else:
            logger.info('skip parsing mime type %s for message: %s', mime_type, message)


class Gmail(object):
    """
    :param config: gmail configuration
    """
    def __init__(self, config=None, proxy_config=None):
        self.config = config
        self.client = None
        if proxy_config and 'host' in proxy_config and 'port' in proxy_config:
            proxy_info = ProxyInfo(socks.PROXY_TYPE_HTTP_NO_TUNNEL,
                                   proxy_config['host'], proxy_config['port'])
        else:
            proxy_info = None
        self.http = Http(proxy_info=proxy_info)
        self.var_dir = self.config['var_dir']
        if not exists(self.var_dir):
            makedirs(self.var_dir)
        self.history_id_f = join(self.var_dir, 'gmail_last_history_id')
        if exists(self.history_id_f):
            with open(self.history_id_f) as fh:
                logger.info('Loaded last gmail history id %d', int(fh.read()))
        else:
            # store an invalid id, which will get renewed on next push event
            self.save_last_history_id('1')

    def _get_credentials(self):
        """Get OAuth credentials

        :return: OAuth credentials
        :rtype: :class:`oauth2client.client.Credentials`
        """
        credential_dir = join(self.var_dir, 'cached_oauth_credentials')
        if not exists(credential_dir):
            makedirs(credential_dir)
        credential_path = join(credential_dir, 'googleapis.json')

        store = Storage(credential_path)
        credentials = store.get()
        if not credentials or credentials.invalid:
            flow = client.flow_from_clientsecrets(self.config['creds'],
                                                  self.config['scope'])
            flow.user_agent = 'Iris Gmail Integration'
            credentials = tools.run_flow(
                flow,
                store,
                tools.argparser.parse_args(args=['--noauth_local_webserver']))
            logger.info('Storing credentials to %s', credential_path)
        else:
            credentials.refresh(self.http)
        return credentials

    def _get_http(self):
        """Construct httplib2.Http resource.

        :return: An object through which HTTP request will be made.
        :rtype: :class:`httplib2.Http`
        """
        return self._get_credentials().authorize(self.http)

    def connect(self):
        """Construct a Resource for interacting with the Gmail v1 API.

        :rtype: `None`
        """
        if self.client is None:
            self.client = build('gmail', 'v1', http=self._get_http())

    def delete_message(
            self,
            msg_id,
            user_id='me'):
        """Delete a Message.

        :param msg_id: ID of Message to delete.
        :param user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
        :rtype: `None`
        """
        self.connect()
        try:
            self.client.users().messages().delete(
                userId=user_id,
                id=msg_id
            ).execute()
        except (socks.HTTPError, errors.HttpError) as error:
            logger.error('An error occurred: %s', error)
        else:
            logger.info('Message with id: %s deleted successfully.', msg_id)

    def get_message(
            self,
            msg_id,
            user_id='me'):
        """Get a Message with given ID.

        :param msg_id: ID of Message to delete.
        :param user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
        :return: A Message.
        :rtype: dict
        """
        self.connect()
        ret = {}
        try:
            ret = self.client.users().messages().get(
                userId=user_id,
                id=msg_id
            ).execute()
        except (socks.HTTPError, errors.HttpError) as error:
            logger.error('An error occurred: %s', error)
        else:
            logger.info('Message snippet: %s', ret.get('snippet'))
        return ret

    @staticmethod
    def get_message_from_batch(
            _,
            message,
            error):
        """Get a Message from BatchHttpRequest.

        :param _:
        :param message:
        :param error:
        :return: A Message.
        :rtype: dict
        """
        ret = {}
        if error is not None:
            logger.error('An error occurred: %s', error)
        else:
            ret = message
            logger.info('Message snippet: %s', ret.get('snippet', ''))
        return ret

    def get_message_id(
            self,
            message):
        """Get Iris message id from Gmail message

        :param message: Gmail message
        :return: Iris message id
        :rtype: int
        """
        try:
            ret = self.get_message_id_from_payload(message)
        except ValueError:
            pass
        else:
            return ret

        try:
            ret = self.get_message_id_from_subject(message)
        except NotImplementedError:
            pass
        else:
            return ret

        try:
            ret = self.get_message_id_from_thread(message)
        except NotImplementedError:
            pass
        else:
            return ret

    @staticmethod
    def get_message_id_from_payload(
            message):
        """Get Iris message id from Gmail message payload

        :param message: Gmail message
        :return: Iris message id
        :rtype: int
        """
        try:
            ret = int(message.split()[0])
        except ValueError:
            raise
        if ret:
            return ret

    @staticmethod
    def get_message_id_from_subject(
            message):
        """Get Iris message id from Gmail message subject

        :param message: Gmail message
        :return: Iris message id
        :rtype: int
        """
        raise NotImplementedError

    @staticmethod
    def get_message_id_from_thread(
            message):
        """Get Iris message id from Gmail message thread

        :param message: Gmail message
        :return: Iris message id
        :rtype: int
        """
        raise NotImplementedError

    def get_mime_message(
            self,
            msg_id,
            user_id='me'):
        """Get a Message and use it to create a MIME Message.

        :param msg_id: The ID of the Message required.
        :param user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
        :return: A MIME Message, consisting of data from Message.
        :rtype: :class:`email.message.Message`
        """
        self.connect()
        ret = None
        try:
            message = self.client.users().messages().get(
                userId=user_id,
                id=msg_id,
                format='raw'
            ).execute()
        except (socks.HTTPError, errors.HttpError) as error:
            logger.error('An error occurred: %s', error)
        else:
            logger.info('Message snippet: %s', message.get('snippet', ''))
            msg_str = urlsafe_b64decode(message.get('raw', '').encode('ASCII'))
            ret = message_from_string(msg_str)
        return ret

    def get_last_history_id(self):
        """read last history id from file"""
        with open(self.history_id_f, 'r') as fh:
            return int(fh.read())

    def save_last_history_id(self, new_id):
        """renew and persist last history id to file"""
        with open(self.history_id_f, 'w') as fh:
            fh.write(str(new_id))

    def list_prev_history(
            self,
            start_history_id,
            end_history_id,
            user_id='me'):
        """List last history of all changes to the user's mailbox With
           start_history_id <= id < end_history_id.

        :param start_history_id: Only return Histories at or after
            start_history_id.
        :param start_history_id: Only return Histories before
            end_history_id.
        :param user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
        :return: A list of last mailbox changes that occurred at or after the
            start_history_id and before end_history_id.
        :rtype: list
        """
        history = self.list_history(start_history_id, user_id)
        prev_h = None
        for h in history:
            if int(h['id']) >= int(end_history_id):
                return prev_h
            prev_h = h
        if not prev_h:
            logger.info('No change found between history %s and %s' % (
                        start_history_id, end_history_id))
        return prev_h

    def list_history(
            self,
            start_history_id='1',
            user_id='me'):
        """List History of all changes to the user's mailbox.

        :param start_history_id: Only return Histories at or after
            start_history_id.
        :param user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
        :return: A list of mailbox changes that occurred after the
            start_history_id.
        :rtype: list
        """
        self.connect()
        history = (self.client.users().history().list(
            userId=user_id,
            startHistoryId=start_history_id
        ).execute())
        ret = history.get('history', [])
        while 'nextPageToken' in history:
            page_token = history.get('nextPageToken')
            history = (self.client.users().history().list(
                userId=user_id,
                startHistoryId=start_history_id,
                pageToken=page_token
            ).execute())
            ret.extend(history.get('history', []))
        return ret

    def modify_message(
            self,
            msg_id,
            msg_labels,
            user_id='me'):
        """Modify the Labels on the given Message.

        :param msg_id: The id of the message required.
        :param msg_labels: The change in labels.
        :param user_id: User's email address. The special value "me"
            can be used to indicate the authenticated user.
        :return: Modified message, containing updated labelIds, id and threadId.
        :rtype: dict
        """
        self.connect()
        ret = {}
        try:
            ret = self.client.users().messages().modify(
                userId=user_id,
                id=msg_id,
                body=msg_labels
            ).execute()
        except (socks.HTTPError, errors.HttpError) as error:
            logger.error('An error occurred: %s', error)
        else:
            label_ids = ret.get('labelIds', [])
            logger.info('Message ID: %s - With Label IDs %s', msg_id, label_ids)
        return ret

    def list_message(self, query, user_id='me'):
        """list message based on query string"""
        self.connect()
        try:
            response = self.client.users().messages().list(userId=user_id,
                                                           q=query).execute()
            if 'messages' in response:
                msg_ids = [m['id'] for m in response['messages']]
            else:
                msg_ids = []

            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = self.client.users().messages().list(
                    userId=user_id,
                    q=query,
                    pageToken=page_token
                ).execute()
                if 'messages' not in response:
                    logger.error('no messages key found in gmail response: %s',
                                 response)
                    continue
                msg_ids.extend([m['id'] for m in response['messages']])

            kill_ids = []
            for msg_id in msg_ids:
                message = self.get_message(msg_id, user_id)
                if is_pointless_messages(message):
                    kill_ids.append(msg_id)
                    continue  # just mark as read and skip
                is_email_processed = False
                for headers, content in process_message(message):
                    is_email_processed = True
                    yield msg_id, headers, content
                if not is_email_processed:
                    kill_ids.append(msg_id)

            if kill_ids:
                logger.info('Skipping and marking %s as read.', kill_ids)
                self.batch_mark_read(kill_ids)
        except (socks.HTTPError, errors.HttpError) as error:
            logger.error('An error occurred: %s' % error)

    def list_unread_message(self, user_id='me'):
        """list all the unread messages"""
        for i, h, c in self.list_message('in:inbox is:unread'):
            yield i, h, c

    @staticmethod
    def parse_gmail_push_data(data):
        notification = loads(urlsafe_b64decode(str(data)))
        return notification.get('emailAddress'), notification.get('historyId')

    def batch_mark_read(self, message_ids, user_id='me'):
        """Mark multiple message IDs as read (remove UNREAD label)

        :param message_ids: list or set of message IDs
        :rtype: None
        """

        self.connect()

        message_ids = list(message_ids)

        messages_per_batch = 500
        pos = 0

        # Batch modify messages in chunks of 500, as there is an upper limit on the number
        # of messages per batch call.
        # https://developers.google.com/gmail/api/v1/reference/users/messages/batchModify
        while True:
            new_pos = pos + messages_per_batch
            ids = message_ids[pos:new_pos]
            pos = new_pos
            if not ids:
                break

            body = {
                'ids': ids,
                'addLabelIds': [],
                'removeLabelIds': ['UNREAD']
            }

            try:
                self.client.users().messages().batchModify(
                    userId=user_id,
                    body=body
                ).execute()
            except (socks.HTTPError, errors.HttpError):
                logger.exception('Failed batch marking messages as read: %s', ids)
            else:
                logger.info('Successfully marked messages as read: %s', ids)

    def process_push_notification(
            self,
            data=''):
        """Process push notification from Gmail.

        :param data: message data from Gmail push notification POST payload
        :return: whether or not processing the push notification completed
        :rtype: bool
        """
        self.connect()
        user_id, history_id = self.parse_gmail_push_data(data)
        last_history_id = self.get_last_history_id()
        if last_history_id < history_id:
            try:
                history = self.list_prev_history(last_history_id, history_id)
            except (socks.HTTPError, errors.HttpError) as error:
                # ref: https://developers.google.com/gmail/api/v1/reference/users/history/list
                # 404 means historyid is out of date, raise it so caller can renew
                # historyid if needed.
                if error.resp['status'] == '404':
                    # renew history_id, still raise error so we can notify gmail
                    # to retry
                    logger.error('Invalid saved last history id: %d, renewing to %s' % (last_history_id, history_id))
                    self.save_last_history_id(int(history_id) - 100)
                raise error
            else:
                msg_ids = set()
                if not history:
                    logger.error('No change between %s and %s' % (
                                 last_history_id, history_id))
                for msg in history.get('messages', []):
                    msg_ids.add(msg.get('id'))
                self.save_last_history_id(history_id)
                # TODO(khrichar): uncomment to switch to batch requests
                # batch = BatchHttpRequest(callback=get_message_from_batch)
                for msg_id in msg_ids:
                    # batch.add(
                    #     self.client.users().messages().get(
                    #         userId=user_id,
                    #         id=msg_id
                    #     )
                    # )
                    # TODO(khrichar): comment to switch to batch requests
                    message = self.get_message(msg_id, user_id) or {}
                    for headers, content in process_message(message):
                        yield msg_id, headers, content
                # try:
                #     batch.execute(http=self.http)
                # except (socks.HTTPError, errors.HttpError) as error:
                #     logger.error('An error occurred: %s', error)
                # else:
                #     for response in batch._responses.itervalues():
                #         message = literal_eval(response[1])
                #         msg_id = message.get('id')
                #         for content, source in process_message(message):
                #             yield msg_id, content, source
