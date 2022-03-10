#!/bin/sh

set -x
set -e

# Set up contexts
CONTEXT1=$(kubectl config view | grep "${CLUSTER_NAME_1}" | head -1 | awk '{print $2}')
CONTEXT2=$(kubectl config view | grep "${CLUSTER_NAME_2}" | head -1 | awk '{print $2}')

# Install Cilium in cluster1
cilium install \
  --context "${CONTEXT1}" \
  --helm-set=cluster.name="${CLUSTER_NAME_1}" \
  --helm-set=cluster.id=1 \
  --helm-set=bpf.monitorAggregation=none \
  --helm-set=ipv4NativeRoutingCIDR=10.0.0.0/9

# Install Cilium in cluster2
cilium install \
  --context "${CONTEXT2}" \
  --helm-set=cluster.name="${CLUSTER_NAME_2}" \
  --helm-set=cluster.id=2 \
  --helm-set=bpf.monitorAggregation=none \
  --helm-set=ipv4NativeRoutingCIDR=10.0.0.0/9 \
  --inherit-ca "${CONTEXT1}"

# Enable Relay
cilium --context "${CONTEXT1}" hubble enable
cilium --context "${CONTEXT2}" hubble enable --relay=false

# Enable cluster mesh
cilium --context "${CONTEXT1}" clustermesh enable
cilium --context "${CONTEXT2}" clustermesh enable

# Wait for cluster mesh status to be ready
cilium --context "${CONTEXT1}" clustermesh status --wait
cilium --context "${CONTEXT2}" clustermesh status --wait

# Connect clusters
cilium --context "${CONTEXT1}" clustermesh connect --destination-context "${CONTEXT2}"

# Wait for cluster mesh status to be ready
cilium --context "${CONTEXT1}" clustermesh status --wait
cilium --context "${CONTEXT2}" clustermesh status --wait

# Port forward Relay
cilium --context "${CONTEXT1}" hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium --context "${CONTEXT1}" connectivity test --debug --multi-cluster "${CONTEXT2}" --test '!/pod-to-.*-nodeport' --all-flows
