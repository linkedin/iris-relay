[![Build Status](https://circleci.com/gh/linkedin/iris-relay.svg?style=shield)](https://circleci.com/gh/linkedin/iris-relay)
[![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)

Iris relay
==========

Stateless reverse proxy for thirdparty service integration with Iris API.


Setup dev environment
---------------------

1. create & source your virtualenv
1. run `python setup.py develop`
1. run `pip install -r dev_requirements.txt`
1. edit ./configs/config.dev.yaml to setup API credential and other settings


Tests
-----

Run tests:

```bash
make unit  # unit tests
make e2e  # e2e tests
make test  # all tests, e2e + unit
```

NOTE: e2e tests requires a running API instance. You can tweak the api host,
port and key setting in `configs/config.dev.yaml`.

Generate test coverage reports:

```bash
make e2e-cov
make unit-cov
```
