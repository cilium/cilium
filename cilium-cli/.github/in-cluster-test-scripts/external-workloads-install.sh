#!/bin/sh

set -x
set -e

cilium install --cluster-name "${CLUSTER_NAME}" --restart-unmanaged-pods=false --config monitor-aggregation=none --config tunnel=vxlan --native-routing-cidr="${CLUSTER_CIDR}"

cilium clustermesh enable
cilium clustermesh status --wait --wait-duration 5m

cilium clustermesh vm create "${VM_NAME}" -n default --ipv4-alloc-cidr 10.192.1.0/30
cilium clustermesh vm status

cilium clustermesh vm install install-external-workload.sh

kubectl -n kube-system create cm install-external-workload-script --from-file=script=install-external-workload.sh
