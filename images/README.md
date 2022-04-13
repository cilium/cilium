# Cilium Images

This directory contains build definitions for Cilium images.

Some of these images are built on top of [`cilium/image-tools`](https://github.com/cilium/image-tools),
anyone reading this document should also read [`cilium/image-tools` documentation](https://github.com/cilium/image-tools/blob/master/README.md).

## Description of Images

### [`builder`](builder/Dockerfile)

This image is based on `runtime` image.

It adds `protoc` and plugins and the Go toolchain.

### [`runtime`](runtime/Dockerfile)

This image is based on [`bpftool`](https://github.com/cilium/image-tools#imagesbpftool),
[`iproute2`](https://github.com/cilium/image-tools#imagesiproute2) and
[`llvm`](https://github.com/cilium/image-tools#imagesllvm) from `cilium/image-tools`.

At present, it also includes [`gops`](https://github.com/google/gops) for
debugging as well as Ubuntu user-space for troubleshooting.

### [`cilium`](cilium/Dockerfile)

It includes `cilium-agent` and other binaries, including `cilium`, `envoy`,
`cilium-health` and `hubble-cli`.

This image is based on `runtime` image, and it contains Ubuntu user-space for
troubleshooting.

### [`operator`](operator/Dockerfile)

This image includes only `cilium-operator` binaries (plus CA certificates),
no other binaries or libraries are included.

For other operators such as: aws, aks, generic, a copy of the same Dockerfile is
used on all of them. Ideally we will re-use the same Dockerfile to build all the
different operators.

### [`hubble-relay`](hubble-relay/Dockerfile)

This image includes only `hubble-relay` binary (plus CA certificates), no other
binaries or libraries are included.

## Tooling

### Making changes

## `runtime` & `builder`

These images are wholly defined by the contents of the image directory, and are
tagged with git tree hash  for the image directory (see
[`cilium/image-tools` documentation](https://github.com/cilium/image-tools#usage)
for details).

If you are making a routine update to the build and runtime images, you can
update all dependent images in the same PR, as long as overall scope of the PR
is just an update to some dependencies and not an implementation of a feature.

The process is described in the [official documentation](https://docs.cilium.io/en/latest/contributing/development/images/#update-cilium-builder-and-cilium-runtime-images)

### Building Locally

One should be able to build all the images locally as long as they have Docker
installed with [`buildx` plug-in](https://docs.docker.com/buildx/working-with-buildx/).

E.g. to build a version fo `runtime` image, run:

```
make -C images runtime-image
```

To push the `runtime` image to a registry, use:
```
make -C images runtime-image PUSH=true REGISTRIES=docker.io/<username>
```

To consume new `runtime` image in `cilium` image, you will need to update
`images/cilium/Dockerfile` manually.

Building and testing `builder` image locally would be accomplished in very
similar manner.

### Testing

Some images have tests, for example when `runtime` image is built, all the
components that it consists of are being tested using `container-structure-test`
tool (see [`cilium/image-tools` docs for details](https://github.com/cilium/image-tools#imagestester)).

### Understanding multi-platform `Dockerfile`

A multi-platform `Dockerfile` pattern applied to Cilium images is as follows:
```
## select host platfrom as linux/amd64, since that's that is what's currently
## available in GitHub Actions;
## it's possible to use `--platform=${BUILDPLATFORM}`, but that requires more
## logic to decide which target is built natively and which one is
## cross-compiled
FROM --platform=linux/amd64 ${CILIUM_BUILDER_IMAGE} as builder

## mount Cilium repo in `GOPATH`, also mount caches
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  ## build natively and install the binaries to /out/linux/amd64
  make build-container install-container \
    DESTDIR=/out/linux/amd64

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
  ## cross-compile for arm64 and install the binaries to /out/linux/arm64
  env GOARCH=arm64 CC=aarch64-linux-gnu-gcc \
    make build-container install-container \
      DESTDIR=/out/linux/arm64 \
      # HOST_CC and HOST_STRIP are required by `bpf/Makefile`
      HOST_CC=aarch64-linux-gnu-gcc HOST_STRIP=aarch64-linux-gnu-strip

## this section will get to run on each of the platform, and in GitHub Actions
## it will run on top of qemu, which is slow, but sufficient for these minor
## steps
FROM ${CILIUM_RUNTIME_IMAGE}
ARG TARGETPLATFORM
LABEL maintainer="maintainer@cilium.io"

COPY --from=builder /out/${TARGETPLATFORM} /

WORKDIR /home/cilium

RUN groupadd -f cilium \
    && echo ". /etc/profile.d/bash_completion.sh" >> /etc/bash.bashrc

CMD ["/usr/bin/cilium"]
```
