#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

svc_file="${dir}/../deployments/kubedns-svc.yaml"
rc_file="${dir}/../deployments/kubedns-rc.yaml"
guestbook_dir="${dir}/../deployments/guestbook"

sed "s/\$cluster-ip/${cluster_dns_ip}/" "${svc_file}.sed" > "${svc_file}"

if [ -n "${NWORKERS}" ]; then
    node_selector="cilium${K8STAG}-node-2"
else
    node_selector="cilium${K8STAG}-master"
fi

sed -e "s/\$kube-master/${kubernetes_master}/" \
    -e "s/\$kube-node-selector/${node_selector}/" \
    "${rc_file}.sed" > "${rc_file}"

sed "s/\$kube-node-selector/${node_selector}/" \
    "${guestbook_dir}/1-redis-master-controller.json.sed" > "${guestbook_dir}/1-redis-master-controller.json"

sed "s/\$kube-node-selector/${node_selector}/" \
    "${guestbook_dir}/3-redis-slave-controller.json.sed" > "${guestbook_dir}/3-redis-slave-controller.json"

sed "s/\$kube-node-selector/${node_selector}/" \
    "${guestbook_dir}/5-guestbook-controller.json.sed" > "${guestbook_dir}/5-guestbook-controller.json"

kubectl create -f "${svc_file}" || true

kubectl create -f "${rc_file}" || true

kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods
