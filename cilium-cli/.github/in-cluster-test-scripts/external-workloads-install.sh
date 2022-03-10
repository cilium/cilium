#!/bin/sh

set -x
set -e

# Install Cilium in cluster
cilium install \
  --helm-set=cluster.name="${CLUSTER_NAME}" \
  --helm-set=bpf.monitorAggregation=none \
  --helm-set=tunnel=vxlan \
  --helm-set=kubeProxyReplacement=strict \
  --helm-set=ipv4NativeRoutingCIDR="${CLUSTER_CIDR}"

# Enable Relay
cilium hubble enable

# Enable cluster mesh
cilium clustermesh enable

# Wait for cluster mesh status to be ready
cilium clustermesh status --wait

# Add VM to cluster mesh
cilium clustermesh vm create "${VM_NAME}" -n default --ipv4-alloc-cidr 10.192.1.0/30
cilium clustermesh vm status

# Create install script for VMs
cilium clustermesh vm install install-external-workload.sh --config debug
kubectl -n kube-system create cm install-external-workload-script --from-file=script=install-external-workload.sh
