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

# Given an app pod and namespace; get corresponding cilium pod

if [ $# -ne 2  ]
then
	echo "Usage: get_cilium_pod.sh <pod> <namespace>"
	exit 1
fi

K8S_NAMESPACE="${K8S_NAMESPACE:-kube-system}"

kubectl get pods -n "${K8S_NAMESPACE}" -owide | grep cilium | grep `kubectl get pods $1 -owide -n $2 | awk '{print $7}' | tail -n1` | awk '{print $1}'
