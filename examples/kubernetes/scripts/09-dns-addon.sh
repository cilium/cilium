#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

set -e

svc_file="${dir}/../deployments/kubedns-svc.yaml"
rc_file="${dir}/../deployments/kubedns-rc.yaml"

sed "s/\$cluster-ip/${cluster_dns_ip}/" "${svc_file}.sed" > "${svc_file}"
sed "s/\$kube-master/${kubernetes_master}/" "${rc_file}.sed" > "${rc_file}"

kubectl create -f "${svc_file}"

kubectl create -f "${rc_file}"

kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods
