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

trap cleanup EXIT

function kill_jobs {
	j=$(jobs -p)
	if [ ! -z "$j" ]; then
		kill -$1 $j 2> /dev/null
	fi
}

function cleanup {
	kill_jobs INT
	sleep 2s
	kill_jobs TERM
}

function get_cilium_pods {
    kubectl -n "${K8S_NAMESPACE}" get pods -l k8s-app=cilium | \
       awk '{print $1}' | \
       grep cilium
}

K8S_NAMESPACE="${K8S_NAMESPACE:-kube-system}"
CONTAINER="${CONTAINER:-cilium-agent}"

while read -r p; do
	kubectl -n "${K8S_NAMESPACE}" exec -c "${CONTAINER}" "${p}" -- "${@}" &
done <<< "$(get_cilium_pods)"

wait
