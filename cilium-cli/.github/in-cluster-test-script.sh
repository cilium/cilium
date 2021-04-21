#!/bin/sh

set -x
set -e

cilium install --cluster-name "${CLUSTER_NAME}" --restart-unmanaged-pods=false --config monitor-aggregation=none --native-routing-cidr="${CLUSTER_CIDR}"

cilium hubble enable

cilium status --wait

cilium hubble port-forward&

cilium connectivity test
