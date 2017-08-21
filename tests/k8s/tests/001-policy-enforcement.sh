#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

set -ex

NAMESPACE="kube-system"
GOPATH="/home/vagrant/go"
DENIED="Result: DENIED"
ALLOWED="Result: ALLOWED"
TEST_NAME="001-policy-enforcement"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"

MINIKUBE="${dir}/../../../examples/minikube"
K8SDIR="${dir}/../../../examples/kubernetes"
GSGDIR="${dir}/deployments/gsg"

ENABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled' -c"
DISABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Disabled' -c"

CILIUM_POD_1=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium -o wide | grep k8s-1 | awk '{ print $1 }')
CILIUM_POD_2=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium -o wide | grep k8s-2 | awk '{ print $1 }')

echo "CILIUM_POD_1: $CILIUM_POD_1"
echo "CILIUM_POD_2: $CILIUM_POD_2"

NUM_ENDPOINTS=4

function cleanup {
  kubectl delete -f "${MINIKUBE}/l3_l4_l7_policy.yaml" 2> /dev/null || true
  kubectl delete -f "${MINIKUBE}/l3_l4_policy_deprecated.yaml" 2> /dev/null || true
  kubectl delete -f "${MINIKUBE}/l3_l4_policy.yaml" 2> /dev/null || true
  kubectl delete -f "${GSGDIR}/demo.yaml" 2> /dev/null || true
  wait_for_no_pods
  kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=default || true
}

function finish_test {
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "1" ${LOGS_DIR}
  cleanup
}

#######################################
# Checks that the provided number of endpoints have policy enforcement enabled
# Globals:
#   ENABLED_CMD
#   NAMESPACE
# Arguments:
#   NUM_EPS: number of endpoints to check
#   CILIUM_POD: name of Cilium pod
# Returns:
#   None
#######################################
function check_endpoints_policy_enabled {
  local NUM_EPS=$1
  local CILIUM_POD=$2

  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement enabled ----"
  kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium endpoint list
  POLICY_ENABLED_COUNT=`eval kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- ${ENABLED_CMD}`
  if [ "${POLICY_ENABLED_COUNT}" -ne "${NUM_EPS}" ] ; then
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium config
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo "---- ${NUM_EPS} endpoints have policy enforcement enabled; continuing ----"
}

#######################################
# Checks that the provided number of endpoints have policy enforcement disabled
# Globals:
#   ENABLED_CMD
#   NAMESPACE
# Arguments:
#   NUM_EPS: number of endpoints to check
#   CILIUM_POD: name of Cilium pod
# Returns:
#   None
#######################################
function check_endpoints_policy_disabled {
  local NUM_EPS=$1
  local CILIUM_POD=$2
  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement disabled ----"
  kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium endpoint list 
  POLICY_DISABLED_COUNT=`eval kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- ${DISABLED_CMD}`
  if [ "${POLICY_DISABLED_COUNT}" -ne "${NUM_EPS}" ] ; then 
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium config
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo  "---- ${NUM_EPS} endpoints have policy enforcement disabled; continuing ----"
}

function import_policy {
  # FIXME Remove workaround once we drop k8s 1.6 support
  # Only test the new network policy with k8s >= 1.7
  if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE create "${MINIKUBE}/l3_l4_policy.yaml"
  else
    k8s_apply_policy $NAMESPACE create "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
  fi
}

function delete_policy {
  # FIXME Remove workaround once we drop k8s 1.6 support
  # Only test the new network policy with k8s >= 1.7
  if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE delete "${MINIKUBE}/l3_l4_policy.yaml"
  else
    k8s_apply_policy $NAMESPACE delete "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
  fi
}

trap finish_test EXIT

cleanup

wait_for_healthy_k8s_cluster 2
wait_for_daemon_set_ready ${NAMESPACE} cilium 2

wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_1}
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_2}

# Patch YAML file from K8s GSG with nodeSelector to a single node so we can properly test the GSG
echo "----- deploying demo application onto cluster -----"
cp "${MINIKUBE}/demo.yaml" "${GSGDIR}/demo.yaml"
patch -p0 "${GSGDIR}/demo.yaml" "${GSGDIR}/minikube-gsg-l7-fix.diff"
kubectl create -f ${GSGDIR}/demo.yaml
wait_for_n_running_pods ${NUM_ENDPOINTS}

echo " ---- pods managed by Cilium Pod 1 ($CILIUM_POD_1) ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium endpoint list
echo " ---- pods managed by Cilium Pod 2 ($CILIUM_POD_2) ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium endpoint list

# Test 1: default mode, K8s, Cilium launched.
# Default behavior is to have policy enforcement disabled for all endpoints that have
# no rules applying to them. Since no policies have been imported, all endpoints should have 
# policy enforcement disabled.
echo "---- Test 1: default mode: test configuration with no policy imported ----"
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 2: default mode, K8s, import policy.
# Import the following policy, which only applies to app3. 
# Since policy enforcement is in 'default' mode for the daemon, policy enforcement 
# should be enabled for only one endpoint (app3), and should be disabled for all other endpoints.
echo "---- Test 2: default mode: test with policy imported  ----"
import_policy
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}

echo "---- Policies in cilium ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium policy get

check_endpoints_policy_enabled 2 ${CILIUM_POD_1}
check_endpoints_policy_disabled 2 ${CILIUM_POD_1}

# Test 3: default mode, K8s, delete policy 
# Delete the aforementioned policy. Since the policy repository is now empty, we expect
# that all endpoints should have policy enforcement disabled.
echo "---- Test 3: default mode: check that policy enforcement for each endpoint is disabled after all policies are removed ----"
delete_policy
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 4: default --> always mode, K8s, no policy imported.
# Change daemon's policy enforcement configuration from 'default' to 'always' with no policy imported. 
# We expect that all endpoints should have policy enforcement enabled after this configuration is applied.
echo "---- Test 4: default --> always mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 5: always --> never mode, K8s, no policy imported.
# We expect that all endpoints should have policy enforcement disabled after this configuration is applied.
echo "---- Test 5: always --> never mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=never
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 6: never mode, K8s, import policy.
# Import a policy while policy enforcement is disabled.
# Policy enforcement should be disabled for all endpoints.
echo "---- Test 6: disabled mode: check that each endpoint has policy enforcement disabled with policy imported ----"
import_policy
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 7: never --> always mode, K8s, policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 7: never --> always mode: check that each endpoint has policy enforcement enabled with policy imported----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 8: always --> default mode, K8s, policy imported.
# Policy enforcement should be enabled for only one endpoint.
echo "---- Test 8: always --> default mode: check that 2 endpoints have policy enforcement enabled with policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=default
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled 2 ${CILIUM_POD_1}

# Test 9: default --> always mode, K8s, policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 9: default --> always mode: check that each endpoint has policy enforcement enabled with policy imported----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 10: always mode, K8s, delete policy.
# Policy enforcement should be 'true' for all endpoints.
echo "---- Test 10: always mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
delete_policy
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 11: always mode, K8s, import policy.
# All endpoints should have policy enforcement enabled.
echo "---- Test 11: always mode: check that each endpoint has policy enforcement enabled with policy imported ----"
import_policy
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 12: always --> never mode, K8s, policy imported.
# All endpoints should have policy enforcement disabled. 
echo "---- Test 12: always --> never mode: check that each endpoint has policy enforcement disabled with policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=never
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 13: never mode, K8s, delete policy.
# All endpoints should have policy enforcement disabled.
echo "---- Test 13: never mode: check that each endpoint has policy enforcement disabled after policy deleted ----"
delete_policy
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 14: never --> always, K8s, no policy imported.
# All endpoints should have policy enforcement enabled.
echo "---- Test 14: never --> always mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 15: always --> default, K8s, no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 15: always --> default mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=default
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 16: default --> never, K8s, no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 16: default --> never mode: check that each endpoint has policy enforcement disabled with no policy ipmorted ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=never
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}

# Test 17: never --> default, K8s, no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 17: never --> default mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_1} -- cilium config PolicyEnforcement=default
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_1} ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS} ${CILIUM_POD_1}
