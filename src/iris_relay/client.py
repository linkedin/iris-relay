# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.


import simplejson as json
import time
import hmac
import hashlib
import base64
from urllib import urlencode
from urllib3.connectionpool import HTTPConnectionPool
import requests


class IrisAuth(requests.auth.AuthBase):
    def __init__(self, app, key):
        if not isinstance(app, bytes):
            app = app.encode('utf-8')
        self.header = b'hmac ' + app + b':'
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        self.HMAC = hmac.new(key, b'', hashlib.sha512)

    def __call__(self, request):
        HMAC = self.HMAC.copy()
        path = str(request.path_url)
        method = str(request.method)
        body = str(request.body or '')
        window = str(int(time.time()) // 5)
        content = '%s %s %s %s' % (window, method, path, body)
        HMAC.update(content.encode('utf-8'))
        digest = base64.urlsafe_b64encode(HMAC.digest())
        request.headers['Authorization'] = self.header + digest
        return request


class MobileClient(requests.Session):
    def __init__(self, app, api_key, api_host, version=0):
        super(MobileClient, self).__init__()
        self.app = app
        self.auth = IrisAuth(app, api_key)
        self.url = api_host + '/v%d/' % version


class IrisClient(HTTPConnectionPool):
    def __init__(self, host, port, user, api_key, version=0, **kwargs):
        super(IrisClient, self).__init__(host, port, **kwargs)
        self.version = version
        self.user = user
        self.HMAC = hmac.new(api_key, '', hashlib.sha512)
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
        HMAC.update(text)
        digest = base64.urlsafe_b64encode(HMAC.digest())

        hdrs['Authorization'] = 'hmac %s:' % self.user + digest

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
        HMAC.update(text)
        digest = base64.urlsafe_b64encode(HMAC.digest())

        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'hmac %s:' % self.user + digest
        }
        return self.urlopen(method, path, headers=headers)
