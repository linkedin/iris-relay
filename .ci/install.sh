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

echo "[*] spin up iris api..."
docker run -d -p 16649:16649 \
    --link mysql \
    -e DOCKER_DB_BOOTSTRAP=1 \
    -e IRIS_CFG_DB_USER=root -e IRIS_CFG_DB_PASSWORD=admin -e IRIS_CFG_DB_HOST=mysql \
    quay.io/iris/iris

echo "[*] create healthcheck status file for relay"
echo 'GOOD' > /tmp/relay_health
