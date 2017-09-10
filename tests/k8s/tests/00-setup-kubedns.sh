#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

NAMESPACE="kube-system"
LOCAL_CILIUM_POD="$(kubectl get pods -n kube-system -o wide | grep $(hostname) | awk '{ print $1 }' | grep cilium)"

wait_for_service_endpoints_ready ${NAMESPACE} kube-dns 53
wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 53 53
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

test_succeeded "${TEST_NAME}"
