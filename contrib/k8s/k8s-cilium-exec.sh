#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

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
    kubectl -n "${K8S_NAMESPACE}" get pods -l k8s-app=cilium -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName | \
       grep cilium
}

K8S_NAMESPACE="${K8S_NAMESPACE:-kube-system}"
CONTAINER="${CONTAINER:-cilium-agent}"

while read -r podName nodeName ; do
	(
		title="==== detail from pod $podName , on node $nodeName "
		msg=$( kubectl -n "${K8S_NAMESPACE}" exec -c "${CONTAINER}" "${podName}" -- "${@}" 2>&1 )
		echo -e "$title \n$msg\n"
	)&
done <<< "$(get_cilium_pods)"

wait
