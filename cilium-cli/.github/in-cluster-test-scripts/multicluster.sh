#!/bin/sh

set -x

CONTEXT1=$(kubectl config view | grep "${CLUSTER_NAME_1}" | head -1 | awk '{print $2}')
CONTEXT2=$(kubectl config view | grep "${CLUSTER_NAME_2}" | head -1 | awk '{print $2}')

cilium --context "${CONTEXT1}" install --cluster-name "${CLUSTER_NAME_1}" --cluster-id 1 --restart-unmanaged-pods=false --config monitor-aggregation=none --native-routing-cidr="${CLUSTER_CIDR_1}"
cilium --context "${CONTEXT1}" hubble enable
cilium --context "${CONTEXT1}" clustermesh enable

cilium --context "${CONTEXT2}" install --cluster-name "${CLUSTER_NAME_2}" --cluster-id 2  --restart-unmanaged-pods=false --config monitor-aggregation=none --native-routing-cidr="${CLUSTER_CIDR_2}" --inherit-ca "${CONTEXT1}"
cilium --context "${CONTEXT2}" hubble enable --relay=false
cilium --context "${CONTEXT2}" clustermesh enable

cilium --context "${CONTEXT1}" clustermesh status --wait
cilium --context "${CONTEXT2}" clustermesh status --wait

cilium --context "${CONTEXT1}" clustermesh connect --destination-context "${CONTEXT2}"

cilium --context "${CONTEXT1}" clustermesh status --wait --wait-duration 5m
cilium --context "${CONTEXT2}" clustermesh status --wait --wait-duration 5m


cilium --context "${CONTEXT1}" hubble port-forward &
sleep 5s

cilium --context "${CONTEXT1}" connectivity test --multi-cluster "${CONTEXT2}" --test '!/pod-to-.*-nodeport' --all-flows

cilium --context "${CONTEXT1}" status
cilium --context "${CONTEXT1}" clustermesh status
cilium --context "${CONTEXT2}" status
cilium --context "${CONTEXT2}" clustermesh status
