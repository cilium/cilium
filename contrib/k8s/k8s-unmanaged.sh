#!/bin/bash
#
# Copyright 2018 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ALL_CEPS=$(kubectl get cep --all-namespaces -o json | jq -r '.items[].metadata | .namespace + "/" + .name')
ALL_PODS=$(kubectl get pods --all-namespaces -o json | jq -r '.items[] | select(.spec.hostNetwork==true | not) | .metadata | .namespace + "/" + .name')

echo "Skipping pods with host networking enabled..."
for pod in $ALL_PODS; do
	if ! echo "$ALL_CEPS" | grep -q "$pod"; then
		echo $pod
	fi
done
