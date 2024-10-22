#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -o errexit
set -o pipefail

# Given a pod name and namespace, get the corresponding cilium pod name.

K8S_NAMESPACE="${K8S_NAMESPACE:-kube-system}"

if [[ $# -ne 2  ]]
then
	echo "Usage: $(basename "$0") <pod> <namespace>" >&2
	exit 1
fi
TARGET_POD_NAME="$1"
TARGET_POD_NAMESPACE="$2"

# Get the target pod's node.
target_pod_node="$(kubectl get pod "${TARGET_POD_NAME}" -n "${TARGET_POD_NAMESPACE}" --no-headers -o custom-columns=:.spec.nodeName)"
if [[ -z "${target_pod_node}" ]]
then
	echo "pod ${TARGET_POD_NAMESPACE}/${TARGET_POD_NAME} has no node assigned" >&2
	exit 1
fi

# Get the Cilium pod running on the target pod's node (using exact node matching).
kubectl get pods -n "${K8S_NAMESPACE}" -l k8s-app=cilium --no-headers -o custom-columns=:.metadata.name,:.spec.nodeName | awk -v node="${target_pod_node}" '$2==node {print $1}'
