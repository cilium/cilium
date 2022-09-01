#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

function all_ceps { kubectl get cep --all-namespaces -o json | jq -r '.items[].metadata | .namespace + "/" + .name'; }
function all_pods { kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork==true | not) | .metadata | .namespace + "/" + .name'; }
 
echo "Skipping pods with host networking enabled..."

sort <(all_ceps) <(all_pods) | uniq -u
