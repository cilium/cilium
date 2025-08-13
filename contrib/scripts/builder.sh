#!/usr/bin/env bash

set -eu

cd "$(dirname "$0")/../.."

CILIUM_BUILDER_IMAGE=$(cat images/cilium/Dockerfile | grep '^ARG CILIUM_BUILDER_IMAGE=' | cut -d '=' -f 2)

GO="$(which go 2> /dev/null || :)"

USER_OPTION=()
USER_PATH="/root"

if [ -z "${RUN_AS_ROOT:-}" ]; then
	USER_OPTION=(--user "$(id -u):$(id -g)")
    USER_PATH="/home/ubuntu"
fi

MOUNT_GOCACHE_DIR=()
if [ -n "${GO}" ]; then
	MOUNT_GOCACHE_DIR=(-v "$(go env GOCACHE):$USER_PATH/.cache/go-build")
fi

if [ -n "${BUILDER_GOCACHE_DIR:-}" ]; then
	MOUNT_GOCACHE_DIR=(-v "${BUILDER_GOCACHE_DIR}:${USER_PATH}/.cache/go-build")
fi

MOUNT_GOMODCACHE_DIR=()
if [ -n "${GO}" ]; then
	MOUNT_GOMODCACHE_DIR=(-v "$(go env GOMODCACHE):/go/pkg/mod")
fi

if [ -n "${BUILDER_GOMODCACHE_DIR:-}" ]; then
	MOUNT_GOMODCACHE_DIR=(-v "${BUILDER_GOMODCACHE_DIR}:/go/pkg/mod")
fi

MOUNT_CCACHE_DIR=()
LOCAL_CCACHE_DIR=$(ccache -k cache_dir 2> /dev/null || :)
if [ -n "${BUILDER_CCACHE_DIR:-}" ]; then
	MOUNT_CCACHE_DIR=(-v "$BUILDER_CCACHE_DIR:$USER_PATH/.cache/ccache")
elif [ -d "$LOCAL_CCACHE_DIR" ]; then
	MOUNT_CCACHE_DIR=(-v "$LOCAL_CCACHE_DIR:$USER_PATH/.cache/ccache")
fi

docker run --rm \
	"${USER_OPTION[@]}" \
	"${MOUNT_GOCACHE_DIR[@]}" \
	"${MOUNT_GOMODCACHE_DIR[@]}" \
	"${MOUNT_CCACHE_DIR[@]}" \
	-v "$PWD":/go/src/github.com/cilium/cilium \
	-w /go/src/github.com/cilium/cilium \
	${DOCKER_ARGS:+$DOCKER_ARGS} \
	"$CILIUM_BUILDER_IMAGE" \
	"$@"
