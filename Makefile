serve:
	gunicorn --reload --access-logfile=- -b '0.0.0.0:16648' --worker-class gevent \
	        -e CONFIG=./configs/config.dev.yaml \
			iris_relay.wrappers.gunicorn:application

e2e:
	py.test ./test/e2etest.py

unit:
	py.test ./test

test:
	make unit
	make e2e

check:
	flake8 src test
	make test

.PHONY: test
