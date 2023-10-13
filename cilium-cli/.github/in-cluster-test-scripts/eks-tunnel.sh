#!/bin/sh

set -x
set -e

# Install Cilium
# We can't get rid of --cluster-name until we fix https://github.com/cilium/cilium-cli/issues/1347.
cilium install \
  --version "${CILIUM_VERSION}" \
  --cluster-name "${CLUSTER_NAME}" \
  --wait=false \
  --set bpf.monitorAggregation=none \
  --datapath-mode=tunnel \
  --set loadBalancer.l7.backend=envoy \
  --set tls.secretsBackend=k8s \
  --set ipam.mode=cluster-pool

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
cilium connectivity test --debug --all-flows --collect-sysdump-on-failure --external-target amazon.com \
  --test '!dns-only,!to-fqdns,!client-egress-l7,!health'
  # workaround for nslookup issues in tunnel mode causing tests to fail reliably
  # TODO: remove once:
  # - https://github.com/cilium/cilium/issues/16975 is fixed
  # - fix has been deployed to a stable branch
  # - cilium-cli default cilium version has been updated to pick up the fix

# Run performance test
cilium connectivity test --perf --perf-duration 1s
