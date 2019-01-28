docker rm -f shader-build-svc || true
docker run --detach --publish 63999:63999 --name svc-shader svc-shader:latest