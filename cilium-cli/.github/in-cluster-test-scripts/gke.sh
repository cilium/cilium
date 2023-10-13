#!/bin/sh

set -x
set -e

# Install Cilium
# We can't get rid of --cluster-name until we fix https://github.com/cilium/cilium-cli/issues/1347.
cilium install \
  --version "${CILIUM_VERSION}" \
  --cluster-name "${CLUSTER_NAME}" \
  --set bpf.monitorAggregation=none \
  --set ipv4NativeRoutingCIDR="${CLUSTER_CIDR}" \
  --set loadBalancer.l7.backend=envoy \
  --set tls.secretsBackend=k8s

# Enable Relay
cilium hubble enable

# Wait for cilium and hubble relay to be ready
# NB: necessary to work against occassional flakes due to https://github.com/cilium/cilium-cli/issues/918
cilium status --wait

# Port forward Relay
cilium hubble port-forward&
sleep 10s
[[ $(pgrep -f "cilium.*hubble.*port-forward|kubectl.*port-forward.*hubble-relay" | wc -l) == 2 ]]

# Run connectivity test
cilium connectivity test --debug --all-flows --collect-sysdump-on-failure --external-target google.com

# Run performance test
cilium connectivity test --perf --perf-duration 1s
