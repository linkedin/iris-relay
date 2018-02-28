from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import requests

import logging
logger = logging.getLogger('saml2')
logger.setLevel('WARN')


class SAML(object):
    def __init__(self, config):
        self.metadata_url_for = config.get('metadata_url_for', {})
        self.metadata = config.get('metadata', {})
        self.acs_format = config['acs_format']
        self.https_acs_format = config['https_acs_format']

    def saml_client_for(self, idp_name=None):
        '''
        Given the name of an IdP, return a configuation.
        The configuration is a hash for use by saml2.config.Config
        '''

        if idp_name not in self.metadata_url_for and idp_name not in self.metadata:
            raise Exception("Settings for IDP '{}' not found".format(idp_name))
        acs_url = self.acs_format % idp_name
        https_acs_url = self.https_acs_format % idp_name

        if self.metadata_url_for:
            rv = requests.get(self.metadata_url_for[idp_name])
            metadata = rv.text
        else:
            metadata = self.metadata[idp_name]

        settings = {
            'metadata': {
                'inline': [metadata],
            },
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (acs_url, BINDING_HTTP_REDIRECT),
                            (acs_url, BINDING_HTTP_POST),
                            (https_acs_url, BINDING_HTTP_REDIRECT),
                            (https_acs_url, BINDING_HTTP_POST)
                        ],
                    },
                    # Don't verify that the incoming requests originate from us via
                    # the built-in cache for authn request ids in pysaml2
                    'allow_unsolicited': True,
                    # Don't sign authn requests, since signed requests only make
                    # sense in a situation where you control both the SP and IdP
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': True,
                },
            },
        }
        spConfig = Saml2Config()
        spConfig.load(settings)
        spConfig.allow_unknown_attributes = True
        saml_client = Saml2Client(config=spConfig)
        return saml_client
