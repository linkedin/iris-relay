from __future__ import absolute_import

import base64
import hashlib
import hmac
import time

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

        path = request.path_url
        method = request.method
        body = request.body or ''
        window = str(int(time.time()) // 30)
        text = '%s %s %s %s' % (window, method, path, body)
        text = text.encode('utf-8')
        HMAC.update(text)

        digest = base64.urlsafe_b64encode(HMAC.digest())
        request.headers['Authorization'] = self.header + digest
        return request


class IrisClient(requests.Session):
    def __init__(self, app, key, api_host, version=0):
        super(IrisClient, self).__init__()
        self.app = app
        self.auth = IrisAuth(app, key)
        self.url = api_host + '/v%d/' % version
