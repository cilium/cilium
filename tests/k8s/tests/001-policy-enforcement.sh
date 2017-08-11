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

LIST_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled\|Disabled'"
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
  echo "------ checking if all endpoints have policy enforcement enabled ------"
  POLICY_ENFORCED=`eval ${LIST_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "Enabled" ]]; then
      cilium config
      cilium endpoint list
      abort "Policy Enabled should be set to 'Enabled' since there are policies added to Cilium"
    fi
  done
}

function check_endpoints_policy_disabled {
  local CILIUM_POD=$1
  echo "------ checking if all endpoints have policy enforcement disabled ------"
  POLICY_ENFORCED=`eval kubectl exec -n ${NAMESPACE} ${CILIUM_POD} --  ${LIST_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "Disabled" ]]; then
      cilium config
      cilium endpoint list
      abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
    fi
  done
}

function check_config_policy_enabled {
        echo "------ checking if cilium daemon has policy enforcement enabled ------"
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
        echo "------ checking if cilium daemon has policy enforcement disabled ------"
        POLICY_ENFORCED=`eval ${CFG_CMD}`
        for line in $POLICY_ENFORCED; do
                if [[ "$line" != "Disabled" ]]; then
                        cilium config
                        cilium endpoint list
                        abort "Policy Enforcement should be set to 'Disabled' for the daemon"
                fi
        done
}


CILIUM_POD_1=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==2{ print $1 }')
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_1}

#TODO - when testing in the k8s multinode env, test with this.

# Since the GSG guide is intended to be used on a single cluster we need
# to add the nodeSelector to a single node so we can properly test the GSG
# cp "${MINIKUBE}/demo.yaml" "${GSGDIR}/demo.yaml"
#patch -p0 "${GSGDIR}/demo.yaml" "${GSGDIR}/minikube-gsg-l7-fix.diff"


# Assume that Cilium is already running and is configured to run with Kubernetes.
# Let's import three applications.

kubectl create -f ${MINIKUBE}/demo.yaml
wait_for_n_running_pods 4


echo "---- Policy in ${CILIUM_POD_1} (should be empty) ----"
kubectl exec ${CILIUM_POD_1} -n ${NAMESPACE} -- cilium policy get

echo "---- checking if all endpoints have policy enforcement disabled since Cilium is running with K8s ----"
check_endpoints_policy_disabled ${CILIUM_POD_1}
