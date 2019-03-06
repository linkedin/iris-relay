# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.


import simplejson as json
import time
import hmac
import hashlib
import base64
# py 2 and 3 compatibility
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
from urllib3.connectionpool import HTTPConnectionPool


class IrisClient(HTTPConnectionPool):
    def __init__(self, host, port, user, api_key, version=0, **kwargs):
        super(IrisClient, self).__init__(host, port, **kwargs)
        self.version = version
        self.user = user
        self.HMAC = hmac.new(api_key.encode('utf8'), b'', hashlib.sha512)
        self.base_path = '/v%s/' % version if version is not None else '/'

    def post(self, endpoint, data, params=None, raw=False, headers=None):
        HMAC = self.HMAC.copy()
        path = self.base_path + endpoint
        method = 'POST'
        hdrs = {}
        window = int(time.time()) // 5
        if not raw:
            hdrs = {'Content-Type': 'application/json'}
            body = json.dumps(data)
        else:
            hdrs = headers if headers else {}
            body = data

        if params:
            path = ''.join([path, '?', urlencode(params)])
        text = '%s %s %s %s' % (window, method, path, body)
        text = text.encode('utf8')
        HMAC.update(text)
        digest = base64.urlsafe_b64encode(HMAC.digest())

        auth_header = 'hmac %s:' % self.user
        hdrs['Authorization'] = auth_header.encode('utf8') + digest

        return self.urlopen(method, path, headers=hdrs, body=body)

    def get(self, endpoint, params=None, raw=False):
        HMAC = self.HMAC.copy()
        path = self.base_path + endpoint
        method = 'GET'
        window = int(time.time()) // 5
        body = ''
        if params:
            path = ''.join([path, '?', urlencode(params)])
        text = '%s %s %s %s' % (window, method, path, body)
        text = text.encode('utf8')
        HMAC.update(text)
        digest = base64.urlsafe_b64encode(HMAC.digest())

        auth_header = 'hmac %s:' % self.user
        headers = {
            'Content-Type': 'application/json',
            'Authorization': auth_header.encode('utf8') + digest
        }
        return self.urlopen(method, path, headers=headers)
