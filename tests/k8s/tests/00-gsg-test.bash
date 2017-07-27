#!/usr/bin/env bash

# This test:
# - K8s GSG in our multi node environment
#

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

set -ex

NAMESPACE="kube-system"
GOPATH="/home/vagrant/go"

MINIKUBE="${dir}/../../../examples/minikube"
K8SDIR="${dir}/../../../examples/kubernetes"
GSGDIR="${dir}/deployments/gsg"

function cleanup {
	kubectl delete -f "${MINIKUBE}/l3_l4_l7_policy.yaml" 2> /dev/null || true
	kubectl delete -f "${MINIKUBE}/l3_l4_policy_deprecated.yaml" 2> /dev/null || true
	kubectl delete -f "${MINIKUBE}/l3_l4_policy.yaml" 2> /dev/null || true
	kubectl delete -f "${GSGDIR}/demo.yaml" 2> /dev/null || true
	kubectl delete -f "${GSGDIR}/cilium-ds.yaml" 2> /dev/null || true
	kubectl delete -f "${K8SDIR}/rbac.yaml" 2> /dev/null || true
}

function gather_logs {
  local CILIUM_ROOT="src/github.com/cilium/cilium"
  local LOGS_DIR="${GOPATH}/${CILIUM_ROOT}/tests/cilium-files/logs"
  echo "storing K8s-relevant logs at: ${LOGS_DIR}"
  mkdir -p ${LOGS_DIR}
  kubectl logs -n kube-system ${CILIUM_POD_1} > ${LOGS_DIR}/cilium-logs-1 || true
  kubectl logs -n kube-system ${CILIUM_POD_2} > ${LOGS_DIR}/cilium-logs-2 || true
  kubectl logs -n kube-system kube-apiserver-k8s-1 > ${LOGS_DIR}/kube-apiserver-k8s-1-logs || true
  kubectl logs -n kube-system kube-controller-manager-k8s-1 > ${LOGS_DIR}/kube-controller-manager-k8s-1-logs || true
  journalctl -au kubelet > ${LOGS_DIR}/kubelet-k8s-1-logs || true
}

function finish_test {
	gather_files k8s-gsg-test ${TEST_SUITE}
	gather_logs
	cleanup
}

trap finish_test exit

cleanup

wait_for_healthy_k8s_cluster 2

echo "----- adding RBAC for Cilium -----"
kubectl create -f "${K8SDIR}/rbac.yaml"

echo "----- deploying Cilium Daemon Set onto cluster -----"
kubectl create -f ${GSGDIR}/cilium-ds.yaml

wait_for_daemon_set_ready ${NAMESPACE} cilium 2

CILIUM_POD_1=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==2{ print $1 }')
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_1}

CILIUM_POD_2=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==3{ print $1 }')
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_2}

echo "----- deploying demo application onto cluster -----"

# Since the GSG guide is intended to be used on a single cluster we need
# to add the nodeSelector to a single node so we can properly test the GSG
cp "${MINIKUBE}/demo.yaml" "${GSGDIR}/demo.yaml"
patch -p0 "${GSGDIR}/demo.yaml" "${GSGDIR}/minikube-gsg-l7-fix.diff"

kubectl create -f "${GSGDIR}/demo.yaml"

wait_for_n_running_pods 4

echo "----- adding L3 L4 policy  -----"

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy.yaml"
else
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

echo "---- Policy in ${CILIUM_POD_1} ----"
kubectl exec ${CILIUM_POD_1} -n ${NAMESPACE} -- cilium policy get

echo "---- Policy in ${CILIUM_POD_2} ----"
kubectl exec ${CILIUM_POD_2} -n ${NAMESPACE} -- cilium policy get

echo "----- testing L3/L4 policy -----"
APP2_POD=$(kubectl get pods -l id=app2 -o jsonpath='{.items[0].metadata.name}')
SVC_IP=$(kubectl get svc app1-service -o jsonpath='{.spec.clusterIP}' )

echo "----- testing app2 can reach app1 (expected behavior: can reach) -----"
RETURN=$(kubectl $ID exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: could not reach pod allowed by L3 L4 policy"
fi

echo "----- testing that app3 cannot reach app 1 (expected behavior: cannot reach)"
APP3_POD=$(kubectl get pods -l id=app3 -o jsonpath='{.items[0].metadata.name}')
RETURN=$(kubectl exec $APP3_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "000" ]]; then
	abort "Error: unexpectedly reached pod allowed by L3 L4 Policy, received return code ${RETURN}"
fi

echo "------ performing HTTP GET on ${SVC_IP}/public from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "------ performing HTTP GET on ${SVC_IP}/private from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/private on port 80"
fi

echo "----- creating L7-aware policy -----"
# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_l7_policy.yaml"
else
    k8s_apply_policy $NAMESPACE "${MINIKUBE}/l3_l4_l7_policy_deprecated.yaml"
fi

echo "---- Policy in ${CILIUM_POD_1} ----"
kubectl exec ${CILIUM_POD_1} -n ${NAMESPACE} -- cilium policy get

echo "---- Policy in ${CILIUM_POD_2} ----"
kubectl exec ${CILIUM_POD_2} -n ${NAMESPACE} -- cilium policy get

echo "------ performing HTTP GET on ${SVC_IP}/public from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "------ performing HTTP GET on ${SVC_IP}/private from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "Error: Unexpected success reaching  ${SVC_IP}/private on port 80"
fi

echo "------ L7 policy success ! ------"
