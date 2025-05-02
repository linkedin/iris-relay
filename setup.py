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
        'pysaml2==7.4.2',
        'PyYAML==6.0.1',
        'gevent==23.9.1',
        'requests==2.32.3',
        'requests-futures==1.0.0',
        'google-api-python-client==2.150.0',
        'SQLAlchemy==1.4.36',
        'PyMySQL==0.10.1',
        'oauth2client==4.1.3',
        'simplejson==3.20.1',
        'slackclient==0.16',
        'twilio==6.44.1',
        'urllib3==1.26.13',
        'falcon==3.1.1',
        'ujson==5.5.0',
        'irisclient==1.3.0',
        'oncallclient==1.1.0',
        'cryptography>=41.0.5,<45'
    ],
    entry_points={
        'console_scripts': [
            'iris-relay-dev = iris_relay.bin.run_server:main'
        ]
    }
)
