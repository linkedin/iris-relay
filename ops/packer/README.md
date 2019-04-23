```mkdir output```
```python gen_packer_cfg.py ./iris-relay.yaml | tail -n +2 > ./output/iris-relay.json```
```packer build -only=docker ./output/iris-relay.json```
```docker run --name iris-relay-mysql -e MYSQL_ROOT_PASSWORD='1234' -d mysql --default-authentication-plugin=mysql_native_password```
```docker run -d --link iris-relay-mysql:mysql -p 16648:16648 -e DOCKER_DB_BOOTSTRAP=1 quay.io/iris/iris-relay```

