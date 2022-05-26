# Copyright (c) LinkedIn Corporation. All rights reserved. Licensed under the BSD-2 Clause license.
# See LICENSE in the project root for license information.


import setuptools
import re


with open('src/iris_relay/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE).group(1)

with open('README.md', 'r') as fd:
    long_description = fd.read()

setuptools.setup(
    name='irisrelay',
    version=version,
    description='Stateless reverse proxy for thirdparty service integration with Iris API.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/linkedin/iris-relay',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3'
    ],
    package_dir={'': 'src'},
    packages=setuptools.find_packages('src'),
    include_package_data=True,
    install_requires=[
        'pysaml2==4.5.0',
        'PyYAML',
        'gevent==21.12.0',
        'requests==2.23.0',
        'requests-futures==0.9.9',
        'google-api-python-client==1.6.2',
        'SQLAlchemy==1.3.0',
        'PyMySQL==0.7.11',
        'oauth2client',
        'simplejson',
        'slackclient==0.16',
        'streql==3.0.2',
        'twilio==6.25.0',
        'urllib3==1.25.11',
        'falcon==1.4.1',
        'ujson==5.2.0',
        'irisclient==1.3.0',
        'oncallclient==1.1.0',
    ],
    entry_points={
        'console_scripts': [
            'iris-relay-dev = iris_relay.bin.run_server:main'
        ]
    }
)
