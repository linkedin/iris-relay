# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.


import setuptools

setuptools.setup(
    name='iris-relay',
    version='0.2.0',
    package_dir={'': 'src'},
    packages=setuptools.find_packages('src'),
    include_package_data=True,
    install_requires=[
        'PyOpenSSL==18.0.0',
        'PyYAML==3.13',
        'gevent==1.4.0',
        'requests-futures==0.9.9',
        # TODO: update google client
        'google-api-python-client==1.4.2',
        'oauth2client==1.4.12',
        'simplejson==3.8.1',
        'slackclient',
        'streql==3.0.2',
        'twilio==6.25.0',
        'urllib3==1.23',
        'falcon==1.1.0',
        'ujson==1.35',
    ],
    entry_points={
        'console_scripts': [
            'iris-relay-dev = iris_relay.bin.run_server:main'
        ]
    }
)
