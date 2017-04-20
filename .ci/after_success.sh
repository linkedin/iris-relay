#!/bin/bash
set -e

pushd ${TRAVIS_BUILD_DIR}

# Kill the `make serve` executed prior to this, so the e2e coverage tests
# will properly run. The sender will still be alive.
killall -9 gunicorn

# TODO
# make combined-cov
