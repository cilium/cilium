#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --disable-check=az-binary \
  --datapath-mode=aks-byocni \
  --wait=false \
  --config monitor-aggregation=none
