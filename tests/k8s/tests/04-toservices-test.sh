#!/usr/bin/env bash

# This tests:
# - Kubernetes ToServices egress policies for headless services

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

log "running test: $TEST_NAME"

headless_dir="${dir}/deployments/headless"

create_policy() {
  if [[ "${k8s_version}" != 1.6.* ]]; then
    kubectl create -f "${headless_dir}/policy.yaml"
  else
    kubectl create -f "${headless_dir}/policy-v1.yaml"
  fi
}

delete_policy() {
  if [[ "${k8s_version}" != 1.6.* ]]; then
    kubectl delete -f "${headless_dir}/policy.yaml"
  else
    kubectl delete -f "${headless_dir}/policy-v1.yaml"
  fi
}

cleanup (){
  delete_policy || true
  kubectl delete -f "${headless_dir}/" || true
}

finish_test (){
  log "finishing test: ${TEST_NAME}"
  cleanup
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "2" ${LOGS_DIR}
  log "finished running test: $TEST_NAME"
}
trap finish_test exit

NAMESPACE="kube-system"
LOCAL_CILIUM_POD="$(kubectl get pods -n kube-system -o wide | grep $(hostname) | awk '{ print $1 }' | grep cilium)"

expected_cidr=198.49.23.144/32

kubectl create -f "${headless_dir}/service.yaml"
kubectl create -f "${headless_dir}/pod.yaml"

kubectl get pods -o wide

wait_for_running_pod toservices
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

log "creating policy, then endpoint, checking if ip is in toCIDR rules of endpoint"

create_policy
kubectl create -f "${headless_dir}/endpoint.yaml"
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

epID=$(kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint list | awk '$3=="Enabled" { print $1 }')
log "endpoint ID: ${epID}"

# TODO: when jq is available in CI switch to this test
#cidr=$(kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint get ${epID} | jq '.[0]["policy"]["cidr-policy"]["egress"][0]' -M)
#if [ "${expected_cidr}" != "${cidr}" ]; then
#  abort "endpoint IP $expected_cidr isn't found in policy egress toCIDR rules"
#fi

x=1
until kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint get ${epID} | grep -q "${expected_cidr}"; do
  if [ $x -eq 10 ]; then
    endpoint=$(kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint get ${epID})
    log "endpoint get output: ${endpoint}"
    abort "endpoint IP $expected_cidr isn't found in policy egress toCIDR rules"
    break
  fi
  to_services_delay
  x=$[x + 1]
done

delete_policy
kubectl delete -f "${headless_dir}/endpoint.yaml"
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

log "creating endpoint, then policy, checking if ip is in toCIDR rules of endpoint"
kubectl create -f "${headless_dir}/endpoint.yaml"
create_policy
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

# TODO: when jq is available in CI switch to this test
#cidr=$(kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint get ${epID} | jq '.[0]["policy"]["cidr-policy"]["egress"][0]')
#if [ "${expected_cidr}" != "${cidr}" ]; then
#  abort "endpoint IP $expected_cidr isn't found in policy egress toCIDR rules"
#fi

x=1
until kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint get ${epID} | grep -q "${expected_cidr}"; do
  if [ $x -eq 10 ]; then
    endpoint=$(kubectl exec -n kube-system ${LOCAL_CILIUM_POD} cilium endpoint get ${epID})
    log "endpoint get output: ${endpoint}"
    abort "endpoint IP $expected_cidr isn't found in policy egress toCIDR rules"
    break
  fi
  to_services_delay
  x=$[x + 1]
done

test_succeeded "${TEST_NAME}"
