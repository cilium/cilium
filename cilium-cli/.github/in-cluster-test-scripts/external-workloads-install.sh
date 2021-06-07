#!/bin/sh

set -x
set -e

# Install Cilium in cluster
cilium install \
  --cluster-name "${CLUSTER_NAME}" \
  --config monitor-aggregation=none \
  --config tunnel=vxlan \
  --kube-proxy-replacement=strict \
  --native-routing-cidr="${CLUSTER_CIDR}"

# Wait for Cilium status to be ready
cilium status --wait

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
