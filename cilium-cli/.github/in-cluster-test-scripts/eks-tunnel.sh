#!/bin/sh

set -x
set -e

# Install Cilium
cilium install \
  --version "${CILIUM_VERSION}" \
  --cluster-name "${CLUSTER_NAME}" \
  --wait=false \
  --config monitor-aggregation=none \
  --datapath-mode=tunnel \
  --helm-set loadBalancer.l7.backend=envoy \
  --helm-set tls.secretsBackend=k8s \
  --ipam cluster-pool

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
