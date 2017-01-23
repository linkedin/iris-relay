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
make test  # all tests, e2e + unit
make e2e  # e2e tests
make unit  # unit tests
```
