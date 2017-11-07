#!/usr/bin/env bash

# This tests:
# Does the agent crash when it receives a malformed CNP from k8s 


dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

case ${k8s_version} in
	1.6*)
    bad_policy_path="${dir}/deployments/bad-cnp/no-endpoint-selector-ciliumv1.yaml"
    log "k8s version is 1.6; using bad policy at ${bad_policy_path}"
		;;
	*)
    bad_policy_path="${dir}/deployments/bad-cnp/no-endpoint-selector-ciliumv2.yaml"
    log "k8s version is >=1.7; using bad policy at ${bad_policy_path}"
		;;
esac

NAMESPACE="kube-system"
LOCAL_CILIUM_POD="$(kubectl get pods -n ${NAMESPACE} -o wide | grep $(hostname) | awk '{ print $1 }' | grep cilium)"

log "running test: $TEST_NAME"

function finish_test {
  log "starting finish_test for ${TEST_NAME}"

  kubectl delete -f "${bad_policy_path}" 2> /dev/null || true

  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "2" ${LOGS_DIR}
  log "finished running test: $TEST_NAME"
}

trap finish_test exit

log "importing CNP missing endpointSelector"
k8s_apply_policy kube-system create "${bad_policy_path}"

log "ensure cilium is still running"
kubectl exec ${LOCAL_CILIUM_POD} -n ${NAMESPACE} -- cilium status
if [ $? -ne 0 ]; then abort "agent died processing CNP without endpointSelector" ; fi

test_succeeded "${TEST_NAME}"
