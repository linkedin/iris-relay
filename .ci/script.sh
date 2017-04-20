#!/bin/bash
set -e

pushd ${TRAVIS_BUILD_DIR}
make serve &
make check
popd
