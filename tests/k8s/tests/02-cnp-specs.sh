#!/usr/bin/env bash

# This tests:
# - Kubernetes cilium network policy multi rule translation and enforcement
# - L7 Policy between services
#
############### Architecture ###############
#
#               +--> Reviews-v1 -+
#               |                +--> Ratings
#  ProductPage--+--> Reviews-v2 -+
#               |
#               +--> Details
#
# All services have port 9080 exposed and have 2 endpoints `/` and `/health`.
# This runtime tests will enforce a policy that will only:
#  - allow Ratings `/health` to be reachable only for `Reviews-v1`
#  - allow Details `/health` AND `/` to be reachable only for `ProductPage`
#
# This means:
#  - ProductPage will not be able to reach directly Ratings service.
#  - Reviews-v1 will not be able to reach Ratings endpoint `/`.
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

bookinfo_dir="${dir}/deployments/bookinfo"

NAMESPACE="kube-system"
LOCAL_CILIUM_POD="$(kubectl get pods -n kube-system -o wide | grep $(hostname) | awk '{ print $1 }' | grep cilium)"

log "running test: $TEST_NAME"

function finish_test {
  log "starting finish_test for ${TEST_NAME}"
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "2" ${LOGS_DIR}
  log "finished running test: $TEST_NAME"
}

trap finish_test exit

log "creating all resources in ${bookinfo_dir}"
kubectl create -f "${bookinfo_dir}"

log "getting all pods"
kubectl get pods -o wide

log "waiting for all K8s pods to be running"
wait_for_running_pod details-v1
wait_for_running_pod ratings-v1
wait_for_running_pod reviews-v1
wait_for_running_pod reviews-v2
wait_for_running_pod productpage-v1
log "done waiting for all K8s pods to be running"

wait_for_service_endpoints_ready default details 9080

# FIXME(ianvernon) - since we have multiple services listening on port 9080, wait_for_service_ready_cilium_pod
# isn't capable of determining which service is ready on that port at this time. GH-1448 will add
# support for JSON output for services which can be parsed and then utilized in 
# wait_for_service_ready_cilium_pod

#wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 9080 9080
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

wait_for_service_endpoints_ready default ratings 9080
#wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 9080 9080
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

wait_for_service_endpoints_ready default reviews 9080
#wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 9080 9080
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

wait_for_service_endpoints_ready default productpage 9080
#wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 9080 9080
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

set +e

# Every thing should be reachable since we are not enforcing any policies

reviews_pod_v1=$(kubectl get pods | grep reviews-v1 | awk '{print $1}')

log "trying to reach ratings:9080/health from reviews pod (should work)"
kubectl exec -t ${reviews_pod_v1} wget -- --tries=5 ratings:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from reviews-v1 to ratings:9080/health service" ; fi

log "trying to reach ratings:9080 from reviews (should work)"
kubectl exec -t ${reviews_pod_v1} wget -- --tries=5 ratings:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from reviews-v1 to ratings:9080 service" ; fi

productpage_v1=$(kubectl get pods | grep productpage-v1 | awk '{print $1}')

log "trying to access details:9080/health from productpage (should work)"
kubectl exec -t ${productpage_v1} wget -- --tries=5 details:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080/health service" ; fi

log "trying to access details:9080 from productpage (should work)"
kubectl exec -t ${productpage_v1} wget -- --tries=5 details:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080 service" ; fi

log "trying to ratings:9080/health from productpage (should work)"
kubectl exec -t ${productpage_v1} wget -- --tries=5 ratings:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to ratings:9080/health service" ; fi

log "trying to reach ratings:9080 from productpage (should work)"
kubectl exec -t ${productpage_v1} wget -- --tries=5 ratings:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to ratings:9080 service" ; fi

cilium_id=$(docker ps -aql --filter=name=cilium-agent)

# Install cilium policies
# FIXME Remove workaround once we drop k8s 1.6 support
# This cilium network policy v2 will work in k8s >= 1.7.x with CRD and v1 with
# TPR in k8s < 1.7.0
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7; adding policies"
    k8s_apply_policy kube-system create "${bookinfo_dir}/policies/cnp.yaml"

    if [ $? -ne 0 ]; then abort "policies were not inserted in kubernetes" ; fi

    log "checking that multi-rules policy was added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=multi-rules 1>/dev/null

    if [ $? -ne 0 ]; then abort "multi-rules policy not in cilium" ; fi
else
    log "k8s version is 1.6; adding policies"
    k8s_apply_policy kube-system create "${bookinfo_dir}/policies/cnp-deprecated.yaml"

    if [ $? -ne 0 ]; then abort "policies were not inserted in kubernetes" ; fi

    log "checking that multi-rules-deprecated policy was added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=multi-rules-deprecated 1>/dev/null

    if [ $? -ne 0 ]; then abort "multi-rules-deprecated policy not in cilium" ; fi
fi

# Reviews should only reach `/health`

reviews_pod_v1=$(kubectl get pods | grep reviews-v1 | awk '{print $1}')

log "checking that reviews can reach ratings:9080/health (should work)"
kubectl exec -t ${reviews_pod_v1} wget -- --tries=5 ratings:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from reviews-v1 to ratings:9080/health service" ; fi

log "checking that reviews can't reach ratings:9080 (shouldn't work)"
kubectl exec -t ${reviews_pod_v1} wget -- --connect-timeout=10 --tries=2 ratings:9080

if [ $? -eq 0 ]; then abort "Error: unexpected success from reviews-v1 to ratings:9080 service" ; fi

# Productpage should reach every page from Details.
productpage_v1=$(kubectl get pods | grep productpage-v1 | awk '{print $1}')

log "checking that productpage can reach details:9080/health (should work)"
kubectl exec -t ${productpage_v1} wget -- --tries=5 details:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080/health service" ; fi

log "checking that productpage can reach details:9080 (should work)"
kubectl exec -t ${productpage_v1} wget -- --tries=5 details:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080 service" ; fi

# But it should fail while reaching out Ratings
log "checking that productpage can't reach ratings:9080/health (shouldn't work)"
kubectl exec -t ${productpage_v1} wget -- --connect-timeout=10 --tries=2 ratings:9080/health

if [ $? -eq 0 ]; then abort "Error: unexpected success from productpage-v1 to ratings:9080/health service" ; fi

log "checking that productpage can't reach ratings:9080 (shouldn't work)"
kubectl exec -t ${productpage_v1} wget -- --connect-timeout=10 --tries=2 ratings:9080

if [ $? -eq 0 ]; then abort "Error: unexpected success from productpage-v1 to ratings:9080 service" ; fi

test_succeeded "${TEST_NAME}"

set +e

log "deleting all resources in ${bookinfo_dir}"
k8s_apply_policy $NAMESPACE delete "${bookinfo_dir}/"

echo "Policies not found error is expected"

log "deleting all policies in ${bookinfo_dir}/policies"
k8s_apply_policy $NAMESPACE delete "${bookinfo_dir}/policies"

log "checking that all policies were deleted in Cilium"
docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=multi-rules 2>/dev/null

if [ $? -eq 0 ]; then abort "multi-rules policy found in cilium; policy should have been deleted" ; fi

