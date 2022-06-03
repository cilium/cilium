#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --cluster-name "${CLUSTER_NAME}" \
  --wait=false \
  --config monitor-aggregation=none

# Enable Relay
cilium hubble enable

# Wait for cilium and hubble relay to be ready
cilium status --wait

# Make sure the 'aws-node' DaemonSet exists but has no scheduled pods
[[ $(kubectl -n kube-system get ds/aws-node -o jsonpath='{.status.currentNumberScheduled}') == 0 ]]

# Port forward Relay
cilium hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium connectivity test --debug --all-flows

# Run performance test
cilium connectivity test --perf --perf-duration 1s
