#!/usr/bin/env bash

set -eu

SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
REPO_ROOT="$SCRIPT_PATH/../.."


CILIUM_BUILDER_IMAGE=${CILIUM_BUILDER_IMAGE:-$(grep '^ARG CILIUM_BUILDER_IMAGE=' "$REPO_ROOT/images/cilium/Dockerfile" | cut -d '=' -f 2)}

ARGS=()

if [ -n "${RUN_AS_NONROOT:-}" ]; then
    ARGS+=(--user "$(id -u):$(id -g)")
fi

if [ -n "${BUILDER_GOCACHE_DIR:-}" ]; then
    ARGS+=(-v "${BUILDER_GOCACHE_DIR}:/root/.cache/go-build")
fi

if [ -n "${BUILDER_GOMODCACHE_DIR:-}" ]; then
    ARGS+=(-v "${BUILDER_GOMODCACHE_DIR}:/go/pkg/mod")
fi

if [ -n "${BUILDER_CCACHE_DIR:-}" ]; then
    ARGS+=(-v "${BUILDER_CCACHE_DIR}:/root/.ccache")
fi

if [ -n "${BUILDER_USE_PWD:-}" ]; then
    # realpath might not be installed, so use a separate variable to get the
    # absolute path of the repo only when $BUILDER_USE_PWD=true.
    # We need the absolute path of the repo to mount it into the container so
    # that make commands executing in a subdirectory
    # (eg: make -C install/kubernetes) can find the root go.mod
    ABS_REPO_ROOT=$(realpath "${REPO_ROOT}")
    ARGS+=(-v "${PWD}:${PWD}" -w "${PWD}" -v "${ABS_REPO_ROOT}:${ABS_REPO_ROOT}")
else
    ARGS+=(-w "/go/src/github.com/cilium/cilium")
fi

docker run --rm \
  "${ARGS[@]}" \
	-v "$REPO_ROOT":/go/src/github.com/cilium/cilium \
	${DOCKER_ARGS:+"$DOCKER_ARGS"} \
	"$CILIUM_BUILDER_IMAGE" \
	"$@"
