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

guestbook_dir="${dir}/deployments/guestbook"

k8s_apply_policy kube-system "${guestbook_dir}/policies/guestbook-policy-redis-deprecated.json"

if [ $? -ne 0 ]; then abort "guestbook-policy-redis-deprecated policy was not inserted in kubernetes" ; fi

kubectl create -f "${guestbook_dir}/policies/guestbook-policy-web.yaml"

if [ $? -ne 0 ]; then abort "guestbook-policy-web policy was not inserted in kubernetes" ; fi

cilium_id=$(docker ps -aq --filter=name=cilium-agent)

set -e

# Set redis on master to force inter-node communication
node_selector="k8s-1"

sed "s/\$kube_node_selector/${node_selector}/" \
    "${guestbook_dir}/1-redis-master-controller.json.sed" > "${guestbook_dir}/1-redis-master-controller.json"

sed "s/\$kube_node_selector/${node_selector}/" \
    "${guestbook_dir}/3-redis-slave-controller.json.sed" > "${guestbook_dir}/3-redis-slave-controller.json"

# Set guestbook on node-2 to force inter-node communication
node_selector="k8s-2"

sed "s/\$kube_node_selector/${node_selector}/" \
    "${guestbook_dir}/5-guestbook-controller.json.sed" > "${guestbook_dir}/5-guestbook-controller.json"

kubectl create -f "${guestbook_dir}"

kubectl get pods -o wide

wait_for_running_pod guestbook

wait_for_service_endpoints_ready default guestbook 3000

set +e

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-web 1>/dev/null

if [ $? -ne 0 ]; then abort "guestbook-web policy not in cilium" ; fi

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis-deprecated 1>/dev/null

if [ $? -ne 0 ]; then abort "guestbook-redis-deprecated policy not in cilium" ; fi

set -e

guestbook_id=$(docker ps -aq --filter=name=k8s_guestbook)

docker exec -i ${guestbook_id} sh -c 'nc redis-master 6379 <<EOF
PING
EOF' || {
        abort "Unable to nc redis-master 6379"
    }

if [[ -n "${lb}" ]]; then
    echo "Testing ingress connectivity between VMs"
    kubectl create -f "${guestbook_dir}/ingress/"
    # FIXME finish this test case once we have LB up and running
fi

kubectl delete -f "${guestbook_dir}/policies/guestbook-policy-redis-deprecated.json"

set +e

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis-deprecated 2>/dev/null

if [ $? -eq 0 ]; then abort "guestbook-redis-deprecated policy found in cilium; policy should have been deleted" ; fi

k8s_apply_policy kube-system "${guestbook_dir}/policies/guestbook-policy-redis.json"

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis 1>/dev/null

if [ $? -ne 0 ]; then abort "guestbook-redis policy not in cilium" ; fi

set -e

docker exec -i ${guestbook_id} sh -c 'nc redis-master 6379 <<EOF
PING
EOF' || {
        abort "Unable to nc redis-master 6379"
    }


echo "SUCCESS!"

set +e

kubectl delete -f "${guestbook_dir}/"

kubectl delete -f "${guestbook_dir}/policies"

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-web 2>/dev/null

if [ $? -eq 0 ]; then abort "guestbook-web policy found in cilium; policy should have been deleted" ; fi

docker exec -i ${cilium_id} cilium policy get io.cilium.k8s-policy-name=guestbook-redis 2>/dev/null

if [ $? -eq 0 ]; then abort "guestbook-redis policy found in cilium; policy should have been deleted" ; fi

if [[ -n "${lb}" ]]; then
    kubectl delete -f "${guestbook_dir}/ingress"
fi

