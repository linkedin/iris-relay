serve:
	gunicorn --reload --access-logfile=- -b '0.0.0.0:16648' --worker-class gevent \
	        -e CONFIG=./configs/config.dev.yaml \
			iris_relay.wrappers.gunicorn:application

e2e:
	python ./tests/e2e.py

unit:
	python ./tests/unit.py

test:
	make unit
	make e2e
