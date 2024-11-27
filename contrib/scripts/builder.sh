#!/usr/bin/env bash

set -eu

SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
REPO_ROOT="$SCRIPT_PATH/../.."


CILIUM_BUILDER_IMAGE=$(grep '^ARG CILIUM_BUILDER_IMAGE=' "$REPO_ROOT/images/cilium/Dockerfile" | cut -d '=' -f 2)

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

docker run --rm \
  "${ARGS[@]}" \
	-v "$REPO_ROOT":/go/src/github.com/cilium/cilium \
	-w /go/src/github.com/cilium/cilium \
	${DOCKER_ARGS:+"$DOCKER_ARGS"} \
	"$CILIUM_BUILDER_IMAGE" \
	"$@"
