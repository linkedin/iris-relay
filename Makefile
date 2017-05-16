serve:
	iris-relay-dev ./configs/config.dev.yaml

e2e:
	py.test -vv ./test/e2etest.py

unit:
	py.test -vv ./test

test:
	make unit
	make e2e

check:
	flake8 src test
	make test

unit-cov:
	COVERAGE_FILE=.coverage.unit py.test --cov-report term-missing --cov=iris ./test

e2e-cov:
	./test/e2etest_coverage.sh

combined-cov:
	rm -f .coverage*
	make unit-cov
	SUPPORT_COMBINED_COVERAGE=1 make e2e-cov
	coverage combine
	coverage report -m

.PHONY: test
