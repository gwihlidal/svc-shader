docker rm -f svc-shader || true
docker run --detach --publish 63999:63999 --name svc-shader gwihlidal/svc-shader:2