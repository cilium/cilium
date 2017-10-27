#!/usr/bin/env bash

# This tests:
# - Kubernetes network policy enforcement in the same namespace
# - Kubernetes services translation to backend IP
# TODO
# - Rewrite the test when the ingress controller is fixed.
# - Reorganize test, remove deprecated policy and duplicated PING from web to
#   redis, when the kubernetes network policy v1beta1 is removed.

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

guestbook_dir="${dir}/deployments/guestbook"

function cleanup {
  kubectl delete -f "${guestbook_dir}/"

  # Only test the new network policy with k8s >= 1.7
  if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7; deleting policies ${guestbook_dir}/policies/guestbook-policy-web.yaml"
    k8s_apply_policy $NAMESPACE delete "${guestbook_dir}/policies/guestbook-policy-web.yaml"
    log "k8s version is 1.7; deleting policies ${guestbook_dir}/policies/guestbook-policy-redis.json"
    k8s_apply_policy $NAMESPACE delete "${guestbook_dir}/policies/guestbook-policy-redis.json"

    log "k8s version is 1.7; checking that guestbook-redis policy is added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis 2>/dev/null
    if [ $? -eq 0 ]; then abort "guestbook-redis policy found in cilium; policy should have been deleted" ; fi

    log "k8s version is 1.7; checking that guestbook-web policy is added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-web 2>/dev/null
    if [ $? -eq 0 ]; then abort "guestbook-web policy found in cilium; policy should have been deleted" ; fi
  else
    # guestbook-redis was previously removed
    log "k8s version is 1.6; deleting ${guestbook_dir}/policies/guestbook-policy-web-deprecated.yaml"
    k8s_apply_policy $NAMESPACE delete "${guestbook_dir}/policies/guestbook-policy-web-deprecated.yaml"

    log "k8s version is 1.6; checking that guestbook-web-deprecated policy is added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-web-deprecated 2>/dev/null
    if [ $? -eq 0 ]; then abort "guestbook-web-deprecated policy found in cilium; policy should have been deleted" ; fi
  fi

  if [[ -n "${lb}" ]]; then
      log "lb mode is enabled; deleting policy ${guestbook_dir}/ingress"
      k8s_apply_policy $NAMESPACE delete "${guestbook_dir}/ingress"
  fi
}

function finish_test {
  log "finishing test: ${TEST_NAME}"
  cleanup 
  gather_files ${TEST_NAME} k8s-tests
  gather_k8s_logs "2" ${LOGS_DIR}
  log "finished running test: $TEST_NAME"
}


trap finish_test exit

# We will test old kubernetes network policy in kubernetes 1.6 and 1.7
k8s_apply_policy kube-system create "${guestbook_dir}/policies/guestbook-policy-redis-deprecated.json"

if [ $? -ne 0 ]; then abort "guestbook-policy-redis-deprecated policy was not inserted in kubernetes" ; fi

# FIXME Remove workaround once we drop k8s 1.6 support
# This cilium network policy v2 will work in k8s >= 1.7.x with CRD and v1 with
# TPR in k8s < 1.7.0
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7; adding policies"
    k8s_apply_policy kube-system create "${guestbook_dir}/policies/guestbook-policy-web.yaml"

    k8s_nodes_policy_status 2 default guestbook-web
else
    log "k8s version is 1.6; adding deprecated policies"
    k8s_apply_policy kube-system create "${guestbook_dir}/policies/guestbook-policy-web-deprecated.yaml"

    k8s_nodes_policy_status 2 default guestbook-web-deprecated
fi

cilium_id=$(docker ps -aql --filter=name=cilium-agent)

# Set redis on master to force inter-node communication
node_selector="k8s-1"

log "setting ${node_selector} to be the node selector in ${guestbook_dir}/1-redis-master-controller.json"
sed "s/\$kube_node_selector/${node_selector}/" \
    "${guestbook_dir}/1-redis-master-controller.json.sed" > "${guestbook_dir}/1-redis-master-controller.json"

log "setting ${node_selector} to be the node selector in ${guestbook_dir}/3-redis-slave-controller.json"
sed "s/\$kube_node_selector/${node_selector}/" \
    "${guestbook_dir}/3-redis-slave-controller.json.sed" > "${guestbook_dir}/3-redis-slave-controller.json"

# Set guestbook on node-2 to force inter-node communication
node_selector="k8s-2"

log "setting ${node_selector} to be the node selector in ${guestbook_dir}/5-guestbook-controller.json"
sed "s/\$kube_node_selector/${node_selector}/" \
    "${guestbook_dir}/5-guestbook-controller.json.sed" > "${guestbook_dir}/5-guestbook-controller.json"

log "creating all resources in ${guestbook_dir}"
kubectl create -f "${guestbook_dir}"

kubectl get pods -o wide

wait_for_running_pod guestbook

wait_for_service_endpoints_ready default guestbook 3000
wait_for_service_ready_cilium_pod ${NAMESPACE} ${LOCAL_CILIUM_POD} 3000 3000
wait_for_cilium_ep_gen k8s ${NAMESPACE} ${LOCAL_CILIUM_POD}

set +e

# FIXME Remove workaround once we drop k8s 1.6 support
# This cilium network policy v2 will work in k8s >= 1.7.x with CRD and v1 with
# TPR in k8s < 1.7.0
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7: checking that guestbook-web policy is added"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-web 1>/dev/null

    if [ $? -ne 0 ]; then abort "guestbook-web policy not in cilium" ; fi
else
    log "k8s version is 1.6; checking that guestbook-web-depcreated policy is added"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-web-deprecated 1>/dev/null

    if [ $? -ne 0 ]; then 
      log "Policies in Cilium: "
      docker exec -i ${cilium_id} cilium policy get
      abort "guestbook-web-deprecated policy not in cilium"
    fi
fi

log "checking that guestbook-redis-deprecated policy is added in Cilium"
docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis-deprecated 1>/dev/null

if [ $? -ne 0 ]; then
  log "Policies in Cilium: "
  docker exec -i ${cilium_id} cilium policy get
  abort "guestbook-redis-deprecated policy not in cilium"
fi

set -e

guestbook_id=$(docker ps -aq --filter=name=k8s_guestbook)

log "trying to nc redis-master 6379 from guestbook container"
docker exec -i ${guestbook_id} sh -c 'nc redis-master 6379 <<EOF
PING
EOF' || {
        abort "Unable to nc redis-master 6379"
    }

if [[ -n "${lb}" ]]; then
    log "Testing ingress connectivity between VMs"
    kubectl create -f "${guestbook_dir}/ingress/"
    # FIXME finish this test case once we have LB up and running
fi

k8s_apply_policy $NAMESPACE delete "${guestbook_dir}/policies/guestbook-policy-redis-deprecated.json"

set +e

log "checking that guestbook-redis-deprecated policy is added in Cilium"
docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis-deprecated 2>/dev/null

if [ $? -eq 0 ]; then abort "guestbook-redis-deprecated policy found in cilium; policy should have been deleted" ; fi

# FIXME Remove workaround once we drop k8s 1.6 support
# Only test the new network policy with k8s >= 1.7
if [[ "${k8s_version}" != 1.6.* ]]; then
    log "k8s version is 1.7, adding guestbook-policy-redis policy to Cilium"
    k8s_apply_policy kube-system create "${guestbook_dir}/policies/guestbook-policy-redis.json"
    
    log "k8s version is 1.7, checking that guestbook-policy-redis policy is added in Cilium"
    docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis 1>/dev/null

    if [ $? -ne 0 ]; then abort "guestbook-redis policy not in cilium" ; fi

    set -e

    log "trying to nc redis-master 6379 from guestbook container"
    docker exec -i ${guestbook_id} sh -c 'nc redis-master 6379 <<EOF
    PING
    EOF' || {
            abort "Unable to nc redis-master 6379"
        }
fi

test_succeeded "${TEST_NAME}"
set +e
