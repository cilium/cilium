#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --helm-set=cluster.name="${CLUSTER_NAME}" \
  --helm-set=bpf.monitorAggregation=none \
  --helm-set=ipv4NativeRoutingCIDR="${CLUSTER_CIDR}"

# Enable Relay
cilium hubble enable

# Port forward Relay
cilium hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium connectivity test --debug --all-flows

# Run performance test
cilium connectivity test --perf --perf-duration 1s
