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
  --set bpf.monitorAggregation=none \
  --set ipam.operator.clusterPoolIPv4PodCIDRList=192.168.0.0/16" # To avoid clashing with the default Service CIDR of AKS (10.0.0.0/16)
