#!/bin/bash

echo "[*] Spinning up mysql through docker"
docker run -d --name mysql \
	-e MYSQL_ROOT_PASSWORD=admin  \
	-e MYSQL_ROOT_HOST=% \
	-d mysql/mysql-server:8.0
