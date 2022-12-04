#!/bin/sh

set -x
set -e

# Set up contexts
CONTEXT1=$(kubectl config view | grep "${CLUSTER_NAME_1}" | head -1 | awk '{print $2}')
CONTEXT2=$(kubectl config view | grep "${CLUSTER_NAME_2}" | head -1 | awk '{print $2}')

# Install Cilium in cluster1
cilium install \
  --version "${CILIUM_VERSION}" \
  --context "${CONTEXT1}" \
  --cluster-name "${CLUSTER_NAME_1}" \
  --cluster-id 1 \
  --config monitor-aggregation=none \
  --ipv4-native-routing-cidr=10.0.0.0/9

# Install Cilium in cluster2
cilium install \
  --version "${CILIUM_VERSION}" \
  --context "${CONTEXT2}" \
  --cluster-name "${CLUSTER_NAME_2}" \
  --cluster-id 2 \
  --config monitor-aggregation=none \
  --ipv4-native-routing-cidr=10.0.0.0/9 \
  --inherit-ca "${CONTEXT1}"

# Enable Relay
cilium --context "${CONTEXT1}" hubble enable
cilium --context "${CONTEXT2}" hubble enable --relay=false

# Wait for cilium and hubble relay to be ready
# NB: necessary to work against occassional flakes due to https://github.com/cilium/cilium-cli/issues/918
cilium --context "${CONTEXT1}" status --wait
cilium --context "${CONTEXT2}" status --wait

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
cilium --context "${CONTEXT1}" connectivity test --debug --multi-cluster "${CONTEXT2}" --test '!/*-deny,!/pod-to-.*-nodeport' \
  --all-flows --collect-sysdump-on-failure
