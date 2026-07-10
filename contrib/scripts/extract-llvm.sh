#!/usr/bin/env bash

set -eu

OUT=${1:-"$PWD"}

cd "$(dirname "$0")/../.."

IMAGE=$(cat images/runtime/Dockerfile | grep '^ARG CILIUM_LLVM_IMAGE=' | cut -d '=' -f 2)
NAME=$(docker create "$IMAGE" /bin/true)
trap 'docker rm "$NAME" > /dev/null' EXIT
mkdir -p "$OUT"
docker export "$NAME" | tar x -C "$OUT"
