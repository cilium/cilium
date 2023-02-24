#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --disable-check=az-binary \
  --datapath-mode=aks-byocni \
  --wait=false \
  --helm-set loadBalancer.l7.backend=envoy \
  --helm-set tls.secretsBackend=k8s \
  --config monitor-aggregation=none
