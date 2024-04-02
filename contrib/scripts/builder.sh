#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/../.."

CILIUM_BUILDER_IMAGE=$(cat images/cilium/Dockerfile | grep '^ARG CILIUM_BUILDER_IMAGE=' | cut -d '=' -f 2)

docker run --rm \
	-v "$PWD":/go/src/github.com/cilium/cilium \
	-w /go/src/github.com/cilium/cilium \
	${DOCKER_ARGS:+"$DOCKER_ARGS"} \
	"$CILIUM_BUILDER_IMAGE" \
	"$@"
