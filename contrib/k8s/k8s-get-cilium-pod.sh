#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Given an app pod and namespace; get corresponding cilium pod

if [ $# -ne 2  ]
then
	echo "Usage: get_cilium_pod.sh <pod> <namespace>"
	exit 1
fi

K8S_NAMESPACE="${K8S_NAMESPACE:-kube-system}"

kubectl get pods -n "${K8S_NAMESPACE}" -owide | grep cilium | grep `kubectl get pods $1 -owide -n $2 | awk '{print $7}' | tail -n1` | awk '{print $1}'
