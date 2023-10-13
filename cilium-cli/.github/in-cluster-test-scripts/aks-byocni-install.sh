#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --datapath-mode=aks-byocni \
  --wait=false \
  --set loadBalancer.l7.backend=envoy \
  --set tls.secretsBackend=k8s \
  --set bpf.monitorAggregation=none
