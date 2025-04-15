#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/../.."

CILIUM_BUILDER_IMAGE=$(cat images/cilium/Dockerfile | grep '^ARG CILIUM_BUILDER_IMAGE=' | cut -d '=' -f 2)

GO=""
if which go > /dev/null; then
    GO="$(which go)"
fi

USER_OPTION=""
USER_PATH="/root"

if [[ "$(uname -s)" == "Darwin" ]]; then
    USER_PATH="/tmp"
fi

if [ -z "${RUN_AS_ROOT:-}" ]; then
    USER_OPTION="--user $(id -u):$(id -g)"
    USER_PATH="$HOME"
fi

MOUNT_GOCACHE_DIR=""
if [ -n "${GO}" ]; then
    MOUNT_GOCACHE_DIR="-v $(go env GOCACHE):$(go env GOCACHE)"
fi

if [ -n "${BUILDER_GOCACHE_DIR:-}" ]; then
    MOUNT_GOCACHE_DIR="-v ${BUILDER_GOCACHE_DIR}:${USER_PATH}/.cache/go-build"
fi

MOUNT_GOMODCACHE_DIR=""
if [ -n "${GO}" ]; then
    MOUNT_GOMODCACHE_DIR="-v $(go env GOMODCACHE):$(go env GOMODCACHE)"
fi

if [ -n "${BUILDER_GOMODCACHE_DIR:-}" ]; then
    MOUNT_GOMODCACHE_DIR="-v ${BUILDER_GOMODCACHE_DIR}:/go/pkg/mod"
fi

MOUNT_CCACHE_DIR=""

if [ -z "${BUILDER_CCACHE_DIR:-}" ]; then
    MOUNT_CCACHE_DIR="-v ${USER_PATH}/.ccache:${USER_PATH}/.ccache"
else
    MOUNT_CCACHE_DIR="-v ${BUILDER_CCACHE_DIR}:${USER_PATH}/.ccache"
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
