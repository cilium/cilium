#!/bin/sh

set -x
set -e

# Install Cilium in cluster
cilium install \
  --version "${CILIUM_VERSION}" \
  --set cluster.name="${CLUSTER_NAME}" \
  --set bpf.monitorAggregation=none \
  --datapath-mode=tunnel \
  --set kubeProxyReplacement=strict \
  --set loadBalancer.l7.backend=envoy \
  --set tls.secretsBackend=k8s \
  --set ipv4NativeRoutingCIDR="${CLUSTER_CIDR}"

# Enable Relay
cilium hubble enable

# Wait for cilium and hubble relay to be ready
# NB: necessary to work against occassional flakes due to https://github.com/cilium/cilium-cli/issues/918
cilium status --wait

# Enable cluster mesh
# Explicitly specify LoadBalancer service type since the default type is NodePort in helm mode.
# Ref: https://github.com/cilium/cilium-cli/pull/1527#discussion_r1177244379
#
# In Helm mode, externalWorkloads.enabled is set to false by default. You need to pass
# --enable-external-workloads flag to enable it.
# Ref: https://github.com/cilium/cilium/pull/25259
cilium clustermesh enable --service-type LoadBalancer --enable-external-workloads

# Wait for cluster mesh status to be ready
cilium clustermesh status --wait

# Add VM to cluster mesh
cilium clustermesh vm create "${VM_NAME}" -n default --ipv4-alloc-cidr 10.192.1.0/30
cilium clustermesh vm status

# Create install script for VMs
cilium clustermesh vm install install-external-workload.sh --config debug
kubectl -n kube-system create cm install-external-workload-script --from-file=script=install-external-workload.sh
