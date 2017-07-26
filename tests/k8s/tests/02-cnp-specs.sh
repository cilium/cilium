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

bookinfo_dir="${dir}/deployments/bookinfo"

NAMESPACE="kube-system"
TEST_NAME="02-cnp-specs"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"

function finish_test {
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "2" ${LOGS_DIR}
}

trap finish_test exit

kubectl create -f "${bookinfo_dir}"

kubectl get pods -o wide

wait_for_running_pod details-v1
wait_for_running_pod ratings-v1
wait_for_running_pod reviews-v1
wait_for_running_pod reviews-v2
wait_for_running_pod productpage-v1

wait_for_service_endpoints_ready default details 9080
wait_for_service_endpoints_ready default ratings 9080
wait_for_service_endpoints_ready default reviews 9080
wait_for_service_endpoints_ready default productpage 9080


# Every thing should be reachable since we are not enforcing any policies

reviews_pod_v1=$(kubectl get pods | grep reviews-v1 | awk '{print $1}')

kubectl exec -t ${reviews_pod_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from reviews-v1 to ratings:9080/health service" ; fi

kubectl exec -t ${reviews_pod_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from reviews-v1 to ratings:9080 service" ; fi


productpage_v1=$(kubectl get pods | grep productpage-v1 | awk '{print $1}')

kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 details:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080/health service" ; fi

kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 details:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080 service" ; fi


kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to ratings:9080/health service" ; fi

kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to ratings:9080 service" ; fi

cilium_id=$(docker ps -aq --filter=name=cilium-agent)

# Install cilium policies
# FIXME Remove workaround once we drop k8s 1.6 support
# This cilium network policy v2 will work in k8s >= 1.7.x with CRD and v1 with
# TPR in k8s < 1.7.0
if [[ "${k8s_version}" == 1.7.* ]]; then
    k8s_apply_policy kube-system "${bookinfo_dir}/policies/cnp.yaml"

    if [ $? -ne 0 ]; then abort "policies were not inserted in kubernetes" ; fi

    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=multi-rules 1>/dev/null

    if [ $? -ne 0 ]; then abort "multi-rules policy not in cilium" ; fi
else
    k8s_apply_policy kube-system "${bookinfo_dir}/policies/cnp-deprecated.yaml"

    if [ $? -ne 0 ]; then abort "policies were not inserted in kubernetes" ; fi

    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=multi-rules-deprecated 1>/dev/null

    if [ $? -ne 0 ]; then abort "multi-rules-deprecated policy not in cilium" ; fi
fi

# Reviews should only reach `/health`

reviews_pod_v1=$(kubectl get pods | grep reviews-v1 | awk '{print $1}')

kubectl exec -t ${reviews_pod_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from reviews-v1 to ratings:9080/health service" ; fi

kubectl exec -t ${reviews_pod_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080

if [ $? -eq 0 ]; then abort "Error: unexpected success from reviews-v1 to ratings:9080 service" ; fi


# Productpage should reach every page from Details.
productpage_v1=$(kubectl get pods | grep productpage-v1 | awk '{print $1}')

kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 details:9080/health

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080/health service" ; fi

kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 details:9080

if [ $? -ne 0 ]; then abort "Error: could not connect from productpage-v1 to details:9080 service" ; fi

# But it should fail while reaching out Ratings
kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080/health

if [ $? -eq 0 ]; then abort "Error: unexpected success from productpage-v1 to ratings:9080/health service" ; fi

kubectl exec -t ${productpage_v1} wget -- --connect-timeout=5 --tries=1 ratings:9080

if [ $? -eq 0 ]; then abort "Error: unexpected success from productpage-v1 to ratings:9080 service" ; fi


echo "SUCCESS!"

set +e

kubectl delete -f "${bookinfo_dir}/"

echo "Policies not found error is expected"

kubectl delete -f "${bookinfo_dir}/policies"

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=multi-rules 2>/dev/null

if [ $? -eq 0 ]; then abort "multi-rules policy found in cilium; policy should have been deleted" ; fi

