#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/../.."

CILIUM_BUILDER_IMAGE=$(cat images/cilium/Dockerfile | grep '^ARG CILIUM_BUILDER_IMAGE=' | cut -d '=' -f 2)

USER_OPTION=""

if [ -n "${RUN_AS_NONROOT:-}" ]; then
    USER_OPTION="--user $(id -u):$(id -g)"
fi

MOUNT_GOCACHE_DIR=""

if [ -n "${BUILDER_GOCACHE_DIR:-}" ]; then
    MOUNT_GOCACHE_DIR="-v ${BUILDER_GOCACHE_DIR}:/root/.cache/go-build"
fi

MOUNT_GOMODCACHE_DIR=""

if [ -n "${BUILDER_GOMODCACHE_DIR:-}" ]; then
    MOUNT_GOMODCACHE_DIR="-v ${BUILDER_GOMODCACHE_DIR}:/go/pkg/mod"
fi

MOUNT_CCACHE_DIR=""

if [ -n "${BUILDER_CCACHE_DIR:-}" ]; then
    MOUNT_CCACHE_DIR="-v ${BUILDER_CCACHE_DIR}:/root/.ccache"
fi

docker run --rm \
	$USER_OPTION \
	$MOUNT_GOCACHE_DIR \
	$MOUNT_GOMODCACHE_DIR \
	$MOUNT_CCACHE_DIR \
	-v "$PWD":/go/src/github.com/cilium/cilium \
	-w /go/src/github.com/cilium/cilium \
	${DOCKER_ARGS:+"$DOCKER_ARGS"} \
	"$CILIUM_BUILDER_IMAGE" \
	"$@"
