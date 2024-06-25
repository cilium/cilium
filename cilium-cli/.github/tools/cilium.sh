#!/usr/bin/env bash

set -ex

CILIUM_CLI_IMAGE_REPO=${CILIUM_CLI_IMAGE_REPO:-quay.io/cilium/cilium-cli-ci}
CILIUM_CLI_IMAGE_TAG=${CILIUM_CLI_IMAGE_TAG:-latest}

docker run \
  --network host \
  -v ~/.kube/config:/root/.kube/config \
  -v "$(pwd)":/root/app \
  -v ~/.aws:/root/.aws \
  -v ~/.azure:/root/.azure \
  -v ~/.config/gcloud:/root/.config/gcloud \
  "$CILIUM_CLI_IMAGE_REPO":"$CILIUM_CLI_IMAGE_TAG" cilium "$@"
