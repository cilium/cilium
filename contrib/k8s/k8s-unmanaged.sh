#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

ALL_CEPS=$(kubectl get cep --all-namespaces -o json | jq -r '.items[].metadata | .namespace + "/" + .name')
ALL_PODS=$(kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork==true | not) | .metadata | .namespace + "/" + .name')

echo "Skipping pods with host networking enabled..."
for pod in $ALL_PODS; do
	if ! echo "$ALL_CEPS" | grep -q "$pod"; then
		echo $pod
	fi
done
