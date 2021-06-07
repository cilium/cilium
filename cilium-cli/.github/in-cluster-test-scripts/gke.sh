#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --cluster-name "${CLUSTER_NAME}" \
  --config monitor-aggregation=none \
  --native-routing-cidr="${CLUSTER_CIDR}"

# Enable Relay
cilium hubble enable

# Wait for Cilium status to be ready
cilium status --wait

# Port forward Relay
cilium hubble port-forward&
sleep 10s

# Run connectivity test
cilium connectivity test --all-flows

# Retrieve Cilium status
cilium status
