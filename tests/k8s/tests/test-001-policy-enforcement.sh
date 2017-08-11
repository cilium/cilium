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

ENABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled' -c"
DISABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Disabled' -c"
CFG_CMD="cilium config | grep Policy | grep -v PolicyTracing | awk '{print \$2}'"

function cleanup {
  #kubectl delete -f "${MINIKUBE}/l3_l4_l7_policy.yaml" 2> /dev/null || true
  #kubectl delete -f "${MINIKUBE}/l3_l4_policy_deprecated.yaml" 2> /dev/null || true
  #kubectl delete -f "${MINIKUBE}/l3_l4_policy.yaml" 2> /dev/null || true
  #kubectl delete -f "${GSGDIR}/demo.yaml" 2> /dev/null || true
  cilium policy delete --all
}

function finish_test {
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "1" ${LOGS_DIR}
  cleanup
}

function check_endpoints_policy_enabled {
  local NUM_EPS=$1
  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement enabled ----"
  cilium endpoint list
  POLICY_ENABLED_COUNT=`eval ${ENABLED_CMD}`
  if [ "${POLICY_ENABLED_COUNT}" -ne "${NUM_EPS}" ] ; then
    cilium config
    cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo "---- ${NUM_EPS} endpoints have policy enforcement enabled; continuing ----"
}

function check_endpoints_policy_disabled {
  local NUM_EPS=$1
  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement disabled ----"
  cilium endpoint list 
  POLICY_DISABLED_COUNT=`eval ${DISABLED_CMD}`
  if [ "${POLICY_DISABLED_COUNT}" -ne "${NUM_EPS}" ] ; then 
    cilium config
    cilium endpoint list
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

trap cleanup EXIT

cleanup
service cilium restart 
#TODO - when testing in the k8s multinode env, test with this.

# Since the GSG guide is intended to be used on a single cluster we need
# to add the nodeSelector to a single node so we can properly test the GSG
# cp "${MINIKUBE}/demo.yaml" "${GSGDIR}/demo.yaml"
#patch -p0 "${GSGDIR}/demo.yaml" "${GSGDIR}/minikube-gsg-l7-fix.diff"


# Test 1: Test default behavior of Cilium when launched in tandem with Kubernetes.
# Assume that Cilium is already running and is configured to run with Kubernetes.
# Default behavior is to have policy enforcement disabled for all endpoints that have
# no rules applying to them. Since no policies have been imported, all endpoints should have 
# policy enforcement disabled.
echo "---- default mode: test configuration with no policy imported ----"
kubectl delete -f ${MINIKUBE}/demo.yaml
kubectl create -f ${MINIKUBE}/demo.yaml
wait_for_n_running_pods 4


echo "---- Policy in ${CILIUM_POD_1} (should be empty) ----"
cilium policy get

check_endpoints_policy_disabled 5

# Test 2: Import policy with 'default' policy enforcement mode.
# Import the following policy, which only applies to app3. 
# Since policy enforcement is in 'default' mode for the daemon, policy enforcement 
# should be enabled for only one endpoint (app3), and should be disabled for all other endpoints.
echo "---- default mode: test with policy imported  ----"

echo "---- Importing L3 CIDR Policy ----"
cat << EOF | policy_import_and_wait -
[{
     "endpointSelector": {"matchLabels":{"k8s:id":"app3"}},
     "egress": [{
         "toCIDR": [ { "ip": "9.9.9.9/32" } ]
     }]
 }]
EOF

echo "---- Policies in cilium ----"
cilium policy get

check_endpoints_policy_enabled 1
check_endpoints_policy_disabled 4

# Test 3: Delete policy and check that all endpoints have policy enforcement disabled.
# Delete the aforementioned policy. Since the policy repository is now empty, we expect
# that all endpoints should have policy enforcement disabled.
echo "---- default mode: check that policy enforcement for each endpoint is disabled after all policies are removed ----"
policy_delete_and_wait "--all"
check_endpoints_policy_disabled 5

# Test 4: Change daemon's policy enforcement configuration from 'default' to 'true' with no policy imported. 
#We expect that all endpoints should have policy enforcement enabled after this configuration is applied.
echo "---- enabled mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
cilium config PolicyEnforcement=always
wait_for_endpoints 5
check_endpoints_policy_enabled 5

# Test 5: Change daemon's policy enforcement configuration from 'true' to false'.
# We expect that all endpoints should have policy enforcement disabled after this configuration is applied.
echo "---- disabled mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
cilium config PolicyEnforcement=never
wait_for_endpoints 5
check_endpoints_policy_disabled 5
