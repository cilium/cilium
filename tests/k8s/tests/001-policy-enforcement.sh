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
CFG_CMD="cilium config | grep Policy | grep -v PolicyTracing | awk '{print \$2}'"

CILIUM_POD_1=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==2{ print $1 }')
CILIUM_POD_2=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==3{ print $1 }')

function cleanup {
  kubectl delete -f "${MINIKUBE}/l3_l4_l7_policy.yaml" 2> /dev/null || true
  kubectl delete -f "${MINIKUBE}/l3_l4_policy_deprecated.yaml" 2> /dev/null || true
  kubectl delete -f "${MINIKUBE}/l3_l4_policy.yaml" 2> /dev/null || true
  #kubectl delete -f "${GSGDIR}/demo.yaml" 2> /dev/null || true
  #cilium policy delete --all 2> /dev/null || true
  kubectl delete -f "${GSGDIR}/demo.yaml" 2> /dev/null || true
  wait_for_n_running_pods 0
  kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=default || true
}

function finish_test {
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "1" ${LOGS_DIR}
  cleanup
}

function check_endpoints_policy_enabled {
  local NUM_EPS=$1
  local CILIUM_POD=$2

  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement enabled ----"
  kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium endpoint list
  POLICY_ENABLED_COUNT=`eval kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- ${ENABLED_CMD}`
  if [ "${POLICY_ENABLED_COUNT}" -ne "${NUM_EPS}" ] ; then
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo "---- ${NUM_EPS} endpoints have policy enforcement enabled; continuing ----"
}

function check_endpoints_policy_disabled {
  local NUM_EPS=$1
  local CILIUM_POD=$2
  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement disabled ----"
  kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- cilium endpoint list 
  POLICY_DISABLED_COUNT=`eval kubectl exec -n ${NAMESPACE} ${CILIUM_POD} -- ${DISABLED_CMD}`
  if [ "${POLICY_DISABLED_COUNT}" -ne "${NUM_EPS}" ] ; then 
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config
    kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo  "---- ${NUM_EPS} endpoints have policy enforcement disabled; continuing ----"
}

function check_config_policy_enabled {
        echo "---- checking if cilium daemon has policy enforcement enabled ----"
        POLICY_ENFORCED=`eval ${CFG_CMD}`
        for line in $POLICY_ENFORCED; do
                if [[ "$line" != "Enabled" ]]; then
                        cilium config
                        cilium endpoint list
                        abort "Policy Enforcement should be set to 'Enabled' for the daemon"
                fi
        done
}

function check_config_policy_disabled {
        echo "---- checking if cilium daemon has policy enforcement disabled ----"
        POLICY_ENFORCED=`eval ${CFG_CMD}`
        for line in $POLICY_ENFORCED; do
                if [[ "$line" != "Disabled" ]]; then
                        cilium config
                        cilium endpoint list
                        abort "Policy Enforcement should be set to 'Disabled' for the daemon"
                fi
        done
}

trap finish_test EXIT

cleanup

# Patch YAML file from K8s GSG with nodeSelector to a single node so we can properly test the GSG
cp "${MINIKUBE}/demo.yaml" "${GSGDIR}/demo.yaml"
patch -p0 "${GSGDIR}/demo.yaml" "${GSGDIR}/minikube-gsg-l7-fix.diff"


# Test 1: Test default behavior of Cilium when launched in tandem with Kubernetes.
# Assume that Cilium is already running and is configured to run with Kubernetes.
# Default behavior is to have policy enforcement disabled for all endpoints that have
# no rules applying to them. Since no policies have been imported, all endpoints should have 
# policy enforcement disabled.
echo "---- Test 1: default mode: test configuration with no policy imported ----"
kubectl create -f ${GSGDIR}/demo.yaml
wait_for_n_running_pods 4

kubectl get pods -n kube-system -o wide

echo "---- Policy in ${CILIUM_POD_2} (should be empty) ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium policy get
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}


# Test 2: Import policy with 'default' policy enforcement mode.
# Import the following policy, which only applies to app3. 
# Since policy enforcement is in 'default' mode for the daemon, policy enforcement 
# should be enabled for only one endpoint (app3), and should be disabled for all other endpoints.
echo "---- Test 2: default mode: test with policy imported  ----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4

echo "---- Policies in cilium ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium policy get

check_endpoints_policy_enabled 2 ${CILIUM_POD_2}
check_endpoints_policy_disabled 2 ${CILIUM_POD_2}

# Test 3: Delete policy and check that all endpoints have policy enforcement disabled.
# Delete the aforementioned policy. Since the policy repository is now empty, we expect
# that all endpoints should have policy enforcement disabled.
echo "---- Test 3: default mode: check that policy enforcement for each endpoint is disabled after all policies are removed ----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_delete_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_delete_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 4: Change daemon's policy enforcement configuration from 'default' to 'true' with no policy imported. 
#We expect that all endpoints should have policy enforcement enabled after this configuration is applied.
echo "---- Test 4: enabled mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 4 ${CILIUM_POD_2}

# Test 5: Change daemon's policy enforcement configuration from 'true' to 'false'.
# We expect that all endpoints should have policy enforcement disabled after this configuration is applied.
echo "---- Test 5: disabled mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=never
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 6: Import a policy while policy enforcement is disabled.
# Policy enforcement should be disabled for all endpoints.
echo "---- Test 6: disabled mode: check that each endpoint has policy enforcement disabled with policy imported ----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

echo "---- Policies in cilium ----"
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 7: Change daemon's policy enforcement configuration from 'false' to 'true' with a policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 7 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 4 ${CILIUM_POD_2}

# Test 8: Change daemon's policy enforcement configuration from 'true' to 'default' with a policy imported.
# Policy enforcement should be enabled for only one endpoint.
echo "---- Test 8 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=default
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 2 ${CILIUM_POD_2}

# Test 9: Change daemon's policy enforcement configuration from 'default' to 'true' with a policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 9 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 4 ${CILIUM_POD_2}

# Test 10: Delete policy while policy enforcement is set to 'true'. 
# Policy enforcement should be 'true' for all endpoints.
echo "---- Test 10 ----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_delete_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_delete_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 4 ${CILIUM_POD_2}

# Test 11: Import a policy while policy enforcement is set to 'true'. 
# All endpoints should have policy enforcement enabled.
echo "---- Test 11 ----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 4 ${CILIUM_POD_2}

# Test 12: Set policy enforcement 'true' --> 'false' while a policy is imported.
# All endpoints should have policy enforcement disabled. 
echo "---- Test 12 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=never
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 13: Delete a policy while policy enforcement is set to 'false.
# All endpoints should have policy enforcement disabled.
echo "---- Test 13 ----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_delete_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_delete_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 14: Set policy enforcement 'false' --> 'true' with no policy imported.
# All endpoints should have policy enforcement enabled.
echo "---- Test 14 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=always
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_enabled 4 ${CILIUM_POD_2}

# Test 15: Set policy enforcement 'true' --> 'default' with no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 15 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=default
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 16: Set policy enforcement 'default' --> 'false' with no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 16 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=never
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}

# Test 17: Set policy enforcement 'false' --> 'default' with no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 17 ----"
kubectl exec -n ${NAMESPACE} ${CILIUM_POD_2} -- cilium config PolicyEnforcement=default
wait_for_k8s_endpoints ${NAMESPACE} ${CILIUM_POD_2} 4
check_endpoints_policy_disabled 4 ${CILIUM_POD_2}
