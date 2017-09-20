#!/usr/bin/env bash

if [[ -n "${IPV6_EXT}" ]]; then
    master_ip=${MASTER_IPV6_PUBLIC:-"FD00::0B"}
    controllers_ips=( "[${master_ip}]" "${master_ip}" )
else
    master_ip=${MASTER_IPV4:-"192.168.33.11"}
    controllers_ips=( "${master_ip}" "${master_ip}" )
fi

kubernetes_master="${controllers_ips[0]}"

# CIDR Range for Pods in cluster.
k8s_cluster_cidr=${K8S_CLUSTER_CIDR:-"10.0.0.0/10"} # 10.0.0.1-10.63.255.254
# Mask size for node cidr in cluster.
k8s_node_cidr_mask_size=${K8S_NODE_CDIR_MASK_SIZE:-"16"} # 1st Node: 10.0.0.1-10.0.255.254, 2nd Node: 10.1.0.1-10.1.255.254...
# CIDR Range for Services in cluster.
k8s_service_cluster_ip_range=${K8S_SERVICE_CLUSTER_IP_RANGE:-"172.20.0.0/24"}
cluster_dns_ip=${K8S_CLUSTER_DNS_IP:-"172.20.0.10"}

k8s_version="v1.8.0-beta.1"
etcd_version="v3.1.0"
