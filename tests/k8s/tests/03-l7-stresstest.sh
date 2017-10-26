#!/usr/bin/env bash

# This tests:
# - L7 stress test
# - Policies across k8s namespaces
#
############### Architecture ###############
#
#  Frontend   ----->  Backend
#
# Backend has a service exposed on port 80.
# This test will run a stress test without any L7 policy loaded, after the
# stress test is completed, it will install a policy and run the stress test
# one more time.

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

log "running test: $TEST_NAME"

function finish_test {
  log "running finish_test for $TEST_NAME"
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "2" ${LOGS_DIR}
  log "finished running test: $TEST_NAME"
}

trap finish_test exit

l7_stresstest_dir="${dir}/deployments/l7-stresstest"

# Set frontend on k8s-1 to force inter-node communication
node_selector="k8s-1"

log "setting node-selector in ${l7_stresstest_dir}/1-frontend.json so frontend runs on $node_selector"
sed "s/\$kube_node_selector/${node_selector}/" \
    "${l7_stresstest_dir}/1-frontend.json.sed" > "${l7_stresstest_dir}/1-frontend.json"

# Set backend on k8s-2 to force inter-node communication
node_selector="k8s-2"

log "setting node-selector in ${l7_stresstest_dir}/2-backend-server.json so backend runs on $node_selector"
sed "s/\$kube_node_selector/${node_selector}/" \
    "${l7_stresstest_dir}/2-backend-server.json.sed" > "${l7_stresstest_dir}/2-backend-server.json"

# Create the namespaces before creating the pods
log "creating K8s namespace qa"
kubectl create namespace qa
log "creating K8s namespace development"
kubectl create namespace development

log "creating all resources in ${l7_stresstest_dir}"
kubectl create -f "${l7_stresstest_dir}"

log "waiting for all resources to be ready"
wait_for_running_pod frontend qa
wait_for_running_pod backend development

wait_for_service_endpoints_ready development backend 80
wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 80 80
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

# frontend doesn't have any endpoints

log "getting information about pods in qa namespace"
kubectl get pods -n qa -o wide
log "getting information about pods in development namespace"
kubectl get pods -n development -o wide
log "getting information about backend service in development namespace"
kubectl describe svc -n development backend

frontend_pod=$(kubectl get pods -n qa | grep frontend | awk '{print $1}')
backend_pod=$(kubectl get pods -n development | grep backend | awk '{print $1}')

backend_svc_ip=$(kubectl get svc -n development | awk 'NR==2{print $2}')

log "Running tests WITHOUT Policy / Proxy loaded"

code=$(kubectl exec -n qa -i ${frontend_pod} -- curl -s -o /dev/null -w "%{http_code}" http://${backend_svc_ip}:80/)

if [ ${code} -ne 200 ]; then abort "Error: unable to connect between frontend and backend:80/" ; fi

kubectl exec -n qa -i ${frontend_pod} -- wrk -t20 -c1000 -d60 "http://${backend_svc_ip}:80/"
kubectl exec -n qa -i ${frontend_pod} -- ab -r -n 1000000 -c 200 -s 60 -v 1 "http://${backend_svc_ip}:80/"

cilium_id=$(docker ps -aql --filter=name=cilium-agent)

# FIXME Remove workaround once we drop k8s 1.6 support
# This cilium network policy v2 will work in k8s >= 1.7.x with CRD and v1 with
# TPR in k8s < 1.7.0
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7; adding policies"
    k8s_apply_policy kube-system create "${l7_stresstest_dir}/policies/cnp.yaml"
    log "checking that policies were added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=l7-stresstest 1>/dev/null
    if [ $? -ne 0 ]; then abort "l7-stresstest policy not in cilium" ; fi
else
    log "k8s version is 1.6; adding policies"
    k8s_apply_policy kube-system create "${l7_stresstest_dir}/policies/cnp-deprecated.yaml"
    log "checking that policies were added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=l7-stresstest-deprecated 1>/dev/null
    if [ $? -ne 0 ]; then abort "l7-stresstest-deprecated policy not in cilium" ; fi
fi

log "Running tests WITH Policy / Proxy loaded"
log "Policy loaded in cilium"

docker exec -i ${cilium_id} cilium policy get

log "===== Netstat ====="

netstat -ltn

code=$(kubectl exec -n qa -i ${frontend_pod} -- curl -s -o /dev/null -w "%{http_code}" http://${backend_svc_ip}:80/)

if [ ${code} -ne 200 ]; then abort "Error: unable to connect between frontend and backend" ; fi

code=$(kubectl exec -n qa -i ${frontend_pod} -- curl --connect-timeout 20 -s -o /dev/null -w "%{http_code}" http://${backend_svc_ip}:80/health)

if [ ${code} -ne 403 ]; then abort "Error: unexpected connection between frontend and backend. wanted HTTP 403, got: HTTP ${code}" ; fi

kubectl exec -n qa -i ${frontend_pod} -- wrk -t20 -c1000 -d60 "http://${backend_svc_ip}:80/"
# FIXME: Due proxy constrains (memory?) it's impossible to execute the test
# with 1000000 requests and 200 parallel connections. It was tested with
# 1 request and 1 parallel connection with no success.
#
#kubectl exec -n qa -i ${frontend_pod} -- ab -r -n 1000000 -c 200 -s 60 -v 1 "http://${backend_svc_ip}:80/"

test_succeeded "${TEST_NAME}"

set +e

log "Not found policy is expected to happen"

log "deleting all resources in ${l7_stresstest_dir}"
k8s_apply_policy $NAMESPACE delete "${l7_stresstest_dir}/"
log "deleting all resources in ${l7_stresstest_dir}/policies"
k8s_apply_policy $NAMESPACE delete "${l7_stresstest_dir}/policies"

log "deleting namespaces qa and development"
kubectl delete namespace qa development

# FIXME Remove workaround once we drop k8s 1.6 support
# This cilium network policy v2 will work in k8s >= 1.7.x with CRD and v1 with
# TPR in k8s < 1.7.0
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7; checking that policies were deleted in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=l7-stresstest 2>/dev/null
    if [ $? -eq 0 ]; then abort "l7-stresstest policy found in cilium; policy should have been deleted" ; fi
else
    log "k8s version is 1.6; checking that policies were deleted in Ciliumd"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=l7-stresstest-deprecated 2>/dev/null
    if [ $? -eq 0 ]; then abort "l7-stresstest-deprecated policy found in cilium; policy should have been deleted" ; fi
fi

