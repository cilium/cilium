#!/bin/bash

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --set cluster.name="${CLUSTER_NAME}" \
  --wait=false \
  --set loadBalancer.l7.backend=envoy \
  --set tls.secretsBackend=k8s \
  --set bpf.monitorAggregation=none

# Enable Relay
cilium hubble enable

# Wait for cilium and hubble relay to be ready
# NB: necessary to work against occassional flakes due to https://github.com/cilium/cilium-cli/issues/918
cilium status --wait

# Make sure the 'aws-node' DaemonSet exists but has no scheduled pods
[[ $(kubectl -n kube-system get ds/aws-node -o jsonpath='{.status.currentNumberScheduled}') == 0 ]]

# Port forward Relay
cilium hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium connectivity test --debug --all-flows --collect-sysdump-on-failure --external-target amazon.com.

# Run performance test
cilium connectivity perf --duration 1s
