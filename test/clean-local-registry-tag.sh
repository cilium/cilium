#!/bin/bash

# This script overwrites provided cilium tag image with minimal docker image in order to prevent registry from bloating over time

set -e

if [[ $1 == *"docker.io"* || $1 == *"quay.io"* ]]; then
	echo "docker.io or quay.io registry detected, cleaning skipped"
	exit 0
fi

BUSYBOX_VERSION=1.31.1

docker pull "docker.io/library/busybox:$BUSYBOX_VERSION"

docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/cilium:$2"
docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/cilium-dev:$2"
docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/operator:$2"
docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/operator-generic:$2"
docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/operator-aws:$2"
docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/operator-azure:$2"
docker tag "busybox:${BUSYBOX_VERSION}" "$1/cilium/hubble-relay:$2"

docker push "$1/cilium/cilium:$2"
docker push "$1/cilium/cilium-dev:$2"
docker push "$1/cilium/operator:$2"
docker push "$1/cilium/operator-generic:$2"
docker push "$1/cilium/operator-aws:$2"
docker push "$1/cilium/operator-azure:$2"
docker push "$1/cilium/hubble-relay:$2"
