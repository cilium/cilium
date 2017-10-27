#!/usr/bin/env bash

# This test:
# - K8s GSG in our multi node environment
#

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
GOPATH="/home/vagrant/go"
DENIED="Final verdict: DENIED"
ALLOWED="Final verdict: ALLOWED"

log "running test: $TEST_NAME"

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
  log "finished running test: $TEST_NAME"
}

trap finish_test exit

cleanup

wait_for_healthy_k8s_cluster 2
wait_for_daemon_set_ready ${NAMESPACE} cilium 2

CILIUM_POD_1=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==2{ print $1 }')
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_1}

CILIUM_POD_2=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | awk 'NR==3{ print $1 }')
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD_2}

log "deploying demo application onto cluster"

# Since the GSG guide is intended to be used on a single cluster we need
# to add the nodeSelector to a single node so we can properly test the GSG
cp "${MINIKUBE}/demo.yaml" "${GSGDIR}/demo.yaml"
patch -p0 "${GSGDIR}/demo.yaml" "${GSGDIR}/minikube-gsg-l7-fix.diff"

kubectl create -f "${GSGDIR}/demo.yaml"

wait_for_n_running_pods 4


# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7; adding L3 L4 policy"
    k8s_apply_policy $NAMESPACE create "${MINIKUBE}/l3_l4_policy.yaml"
else
    log "k8s version is 1.6; adding L3 L4 policy"
    k8s_apply_policy $NAMESPACE create "${MINIKUBE}/l3_l4_policy_deprecated.yaml"
fi

log "Policy in ${CILIUM_POD_1}"
kubectl exec ${CILIUM_POD_1} -n ${NAMESPACE} -- cilium policy get

log "Policy in ${CILIUM_POD_2}"
kubectl exec ${CILIUM_POD_2} -n ${NAMESPACE} -- cilium policy get

log "testing L3/L4 policy"
APP1_POD="$(kubectl get pods -l id=app1 -o jsonpath='{.items[0].metadata.name}')"
APP2_POD=$(kubectl get pods -l id=app2 -o jsonpath='{.items[0].metadata.name}')
APP3_POD=$(kubectl get pods -l id=app3 -o jsonpath='{.items[0].metadata.name}')

SVC_IP=$(kubectl get svc app1-service -o jsonpath='{.spec.clusterIP}' )

log "testing app2 can reach app1 (expected behavior: can reach)"
RETURN=$(kubectl $ID exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: could not reach pod allowed by L3 L4 policy"
fi

log "confirming that \`cilium policy trace\` shows that app2 can reach app1"
diff_timeout "echo $ALLOWED" "kubectl exec -n kube-system $CILIUM_POD_1 --  cilium policy trace --src-k8s-pod default:$APP2_POD --dst-k8s-pod default:$APP1_POD --dport 80 -v | grep \"Final verdict:\""

log "testing that app3 cannot reach app 1 (expected behavior: cannot reach)"
RETURN=$(kubectl exec $APP3_POD -- curl --connect-timeout 15 -s --output /dev/stderr -w '%{http_code}' -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "000" ]]; then
	abort "Error: unexpectedly reached pod allowed by L3 L4 Policy, received return code ${RETURN}"
fi

log "confirming that \`cilium policy trace\` shows that app3 cannot reach app1"
diff_timeout "echo $DENIED" "kubectl exec -n kube-system $CILIUM_POD_1 --  cilium policy trace --src-k8s-pod default:$APP3_POD --dst-k8s-pod default:$APP1_POD -v | grep \"Final verdict:\""

log "performing HTTP GET on ${SVC_IP}/public from app2"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

log "performing HTTP GET on ${SVC_IP}/private from app2"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/private on port 80"
fi

log "creating L7-aware policy"
# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" != 1.6.* ]]; then
    k8s_apply_policy $NAMESPACE create "${MINIKUBE}/l3_l4_l7_policy.yaml"
else
    k8s_apply_policy $NAMESPACE create "${MINIKUBE}/l3_l4_l7_policy_deprecated.yaml"
fi

log "Policy in ${CILIUM_POD_1}"
kubectl exec ${CILIUM_POD_1} -n ${NAMESPACE} -- cilium policy get

log "Policy in ${CILIUM_POD_2}"
kubectl exec ${CILIUM_POD_2} -n ${NAMESPACE} -- cilium policy get

log "performing HTTP GET on ${SVC_IP}/public from app2"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

log "performing HTTP GET on ${SVC_IP}/private from app2"
RETURN=$(kubectl exec $APP2_POD -- curl --connect-timeout 15 -s --output /dev/stderr -w '%{http_code}' --connect-timeout 15 http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "Error: Unexpected success reaching  ${SVC_IP}/private on port 80"
fi

test_succeeded "${TEST_NAME}"
