Iris-relay under Docker
=========================

### Get started

Build container. This installs all dependencies as well as copies all iris-relay source code.

    docker build -t iris-relay .

Edit iris-relay's config file to reflect where you have iris-api running as well as third party
API settings:

    vim docker/config/config.yaml

Run it, with bind mounts to give access to iris relay config file:

    docker run -p 16648:16648 -v `pwd`/docker/config:/home/iris/config -t iris-relay

You can optionally bind mount log directories for uwsgi/nginx as well as keep the gmail metadata dir persistent:

    mkdir -p docker/logs
    docker run -p 16648:16648 -v `pwd`/docker/config:/home/iris/config \
    -v `pwd`/docker/logs/nginx:/home/iris/var/log/nginx  \
    -v `pwd`/docker/logs/uwsgi:/home/iris/var/log/uwsgi \
    -v `pwd`/docker/var:/home/iris/var/relay \
    -t iris-relay

You can then hit `http://localhost:16648` to access iris-relay running within the docker.

### Quick commands

Check what containers are running:

    docker ps

Kill and remove a container:

    docker rm -f $ID

Execute a bash shell inside container while it's running:

    docker exec -i -t $ID /bin/bash
