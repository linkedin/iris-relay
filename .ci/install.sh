#!/bin/bash
set -e

CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

travis_retry() {
  local result=0
  local count=1
  while [ $count -le 3 ]; do
    [ $result -ne 0 ] && {
      echo -e "\n${ANSI_RED}The command \"$@\" failed. Retrying, $count of 3.${ANSI_RESET}\n" >&2
    }
    "$@"
    result=$?
    [ $result -eq 0 ] && break
    count=$(($count + 1))
    sleep 1
  done

  [ $count -gt 3 ] && {
    echo -e "\n${ANSI_RED}The command \"$@\" failed 3 times.${ANSI_RESET}\n" >&2
  }

  return $result
}

echo "[*] spin up mysql..."
bash ${CI_DIR}/run_mysql_docker.sh

echo "[*] install iris-relay dependencies..."
pushd ${TRAVIS_BUILD_DIR}
	echo "[*] installing app dependencies..."
	travis_retry python setup.py develop
	echo "[*] pip installing dev_requirements.txt..."
	travis_retry pip install -r dev_requirements.txt
popd


echo "[*] setup mysql with schema and dummy data..."
IRIS_REPO_URL=https://raw.githubusercontent.com/linkedin/iris/master

travis_retry wget "${IRIS_REPO_URL}/.ci/setup_mysql.sh"
mkdir db
pushd db
	travis_retry wget "${IRIS_REPO_URL}/db/schema_0.sql"
	travis_retry wget "${IRIS_REPO_URL}/db/dummy_data.sql"
popd
ls -l db
bash ./setup_mysql.sh

echo "[*] run iris instance for e2e test..."
mkdir -p iris/config
pushd iris
	wget "${IRIS_REPO_URL}/configs/config.dev.yaml" > config/config.yaml
popd

mkdir -p iris/logs/{nginx,uwsgi}

docker run -p 16649:16649 \
	-v `pwd`/iris/config:/home/iris/config \
	quay.io/iris/iris

echo "[*] create healthcheck status file for relay"
echo 'GOOD' > /tmp/relay_health
