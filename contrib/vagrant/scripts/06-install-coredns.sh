#!/usr/bin/env bash
#
# Configures, deletes, and creates kube-dns in the cluster defined in kubectl
# to configure the spec files. It will use default values from ./helpers.bash
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

log "Installing coredns into kubectl cluster..."

set -e

deployments_dir="${dir}/../deployments"
cm_file="${deployments_dir}/coredns-cm.yaml"
svc_file="${deployments_dir}/coredns-svc.yaml"
controller_file="${deployments_dir}/coredns-controller.yaml"
sa_file="${deployments_dir}/coredns-sa.yaml"

sed "s/\$DNS_SERVER_IPV6/${cluster_dns_ipv6}/;s/\$DNS_SERVER_IP/${cluster_dns_ip}/" "${svc_file}.sed" > "${svc_file}"

sed -e "s/\$DNS_DOMAIN/cluster.local/" \
    "${cm_file}.sed" > "${cm_file}"

kubectl delete --grace-period=5 -f "${controller_file}" 2>/dev/null || true
kubectl delete --grace-period=5 -f "${svc_file}" 2>/dev/null || true
kubectl delete --grace-period=5 -f "${sa_file}" 2>/dev/null || true
kubectl delete --grace-period=5 -f "${cm_file}" 2>/dev/null || true
kubectl create -f "${cm_file}" || true
kubectl create -f "${sa_file}" || true
kubectl create -f "${svc_file}" || true
kubectl create -f "${controller_file}" || true &

kubectl --namespace=kube-system get svc
kubectl --namespace=kube-system get pods

log "Installing coredns into kubectl cluster... DONE!"
