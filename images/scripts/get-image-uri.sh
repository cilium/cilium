#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ROOT_DIR=${ROOT_DIR:-"$(git rev-parse --show-toplevel)"}
DOCKERFILE="$ROOT_DIR/images/cilium/Dockerfile"
BASE_IMAGE_REGISTRY=${BASE_IMAGE_REGISTRY:-}

case "${1:-}" in
  builder) ARG_NAME="CILIUM_BUILDER_IMAGE" ;;
  runtime) ARG_NAME="CILIUM_RUNTIME_IMAGE" ;;
  envoy) ARG_NAME="CILIUM_ENVOY_IMAGE" ;;
  *)
    echo "Usage: $0 {builder|runtime|envoy}" >&2
    exit 1
    ;;
esac

image=$(grep -E "^ARG[[:space:]]+$ARG_NAME=" "$DOCKERFILE" | cut -d= -f2-)

if [ -z "$image" ]; then
  echo "Could not find ARG $ARG_NAME in $DOCKERFILE" >&2
  exit 1
fi

if [ -n "$BASE_IMAGE_REGISTRY" ]; then
  image="${BASE_IMAGE_REGISTRY}/${image#*/}"
fi

echo "$image"
