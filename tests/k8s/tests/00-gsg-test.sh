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
DENIED="Result: DENIED"
ALLOWED="Result: ALLOWED"
TEST_NAME="00-gsg-test"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"

MINIKUBE="${dir}/../../../examples/minikube"
K8SDIR="${dir}/../../../examples/kubernetes"
GSGDIR="${dir}/deployments/gsg"

function cleanup {
  kubectl delete -f "${MINIKUBE}/l3_l4_l7_policy.yaml" 2> /dev/null || true
  kubectl delete -f "${MINIKUBE}/l3_l4_policy_deprecated.yaml" 2> /dev/null || true
  kubectl delete -f "${MINIKUBE}/l3_l4_policy.yaml" 2> /dev/null || true
  kubectl delete -f "${GSGDIR}/demo.yaml" 2> /dev/null || true
}

function finish_test {
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "1" ${LOGS_DIR}
  cleanup
}

trap finish_test exit

cleanup

wait_for_healthy_k8s_cluster 2
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
APP1_POD="$(kubectl get pods -l id=app1 -o jsonpath='{.items[0].metadata.name}')"
APP2_POD=$(kubectl get pods -l id=app2 -o jsonpath='{.items[0].metadata.name}')
APP3_POD=$(kubectl get pods -l id=app3 -o jsonpath='{.items[0].metadata.name}')

SVC_IP=$(kubectl get svc app1-service -o jsonpath='{.spec.clusterIP}' )

echo "----- testing app2 can reach app1 (expected behavior: can reach) -----"
RETURN=$(kubectl $ID exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: could not reach pod allowed by L3 L4 policy"
fi

echo "----- confirming that \`cilium policy trace\` shows that app2 can reach app1"
k8s_policy_trace $ALLOWED $NAMESPACE $CILIUM_POD_1 --src-k8s-pod default:$APP2_POD --dst-k8s-pod default:$APP1_POD

echo "----- testing that app3 cannot reach app 1 (expected behavior: cannot reach)"
RETURN=$(kubectl exec $APP3_POD -- curl -s --output /dev/stderr -w '%{http_code}' -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "000" ]]; then
	abort "Error: unexpectedly reached pod allowed by L3 L4 Policy, received return code ${RETURN}"
fi

echo "----- confirming that \`cilium policy trace\` shows that app3 cannot reach app1"
k8s_policy_trace $ALLOWED $NAMESPACE $CILIUM_POD_1 --src-k8s-pod default:$APP3_POD --dst-k8s-pod default:$APP1_POD

echo "------ performing HTTP GET on ${SVC_IP}/public from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "------ performing HTTP GET on ${SVC_IP}/private from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' http://${SVC_IP}/private || true)
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
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "------ performing HTTP GET on ${SVC_IP}/private from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 15 http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "Error: Unexpected success reaching  ${SVC_IP}/private on port 80"
fi

echo "------ L7 policy success ! ------"
