# svc-shader

A gRPC micro-service that exposes a variety of GPU shader compilers under a common cloud-based abstraction.

[![Build Status](https://travis-ci.org/gwihlidal/svc-shader.svg?branch=master)](https://travis-ci.org/gwihlidal/svc-shader)

Hub: https://hub.docker.com/r/gwihlidal/svc-shader/

## Extensive documentation

- https://www.wihlidal.com/blog/pipeline/2018-09-15-linux-dxc-docker/
- https://www.wihlidal.com/blog/pipeline/2018-09-16-dxil-signing-post-compile/
- https://www.wihlidal.com/blog/pipeline/2018-09-17-linux-fxc-docker/
- https://www.wihlidal.com/blog/pipeline/2018-12-28-containerized_shader_compilers/

## Updating Compilers

The `svc-shader` image inherits from the `docker-shader` image. A new `docker-shader` image must be built when compilers need to be updated. Once there is a new `docker-shader` image, the `svc-shader` image and scripts should be modified to point to the new version.

The `docker-shader` image can be modified as per [these instructions](https://github.com/gwihlidal/docker-shader#updating-compilers).

Before building and pushing a new image, increment the version number at the top of `Makefile`

Build and push a new image by running `"make push"`, `image.sh`, or by running the commands manually (substituting in the correct variable values):

```bash
docker build -t $(NS)/$(REPO):$(VERSION) .
docker push $(NS)/$(REPO):$(VERSION)
```

Example:

```bash
docker build -t gwihlidal/svc-shader:15 .
docker push gwihlidal/svc-shader:15
```

Note, you won't have permission to push to the `gwihlidal` namespace on Docker Hub, so make sure to use your own account or custom container registry like https://cloud.google.com/container-registry/

Example of a version update:

https://github.com/gwihlidal/svc-shader/commit/a845f5bffeadb76b0cb77ea4bd4525d2b58798fe
