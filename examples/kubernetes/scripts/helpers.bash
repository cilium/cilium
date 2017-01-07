#!/usr/bin/env bash

# CIDR Range for Nodes in cluster.
k8s_cluster_range="172.16.0.0/24"

controllers_ips=("192.168.33.11" "192.168.34.11")
workers_ips=("192.168.33.12" "192.168.34.12")

# CIDR Range for Pods in cluster.
k8s_cluster_cidr="10.200.0.0/13" # 10.200.0.1-10.207.255.254
# Mask size for node cidr in cluster.
k8s_node_cidr_mask_size="16" # 10.200.0.1-10.200.255.254, 10.201.0.1-10.201.255.254...

# CIDR Range for Services in cluster.
k8s_service_cluster_ip_range="10.32.0.0/24"
k8s_master_service_ip="10.32.0.1"
cluster_dns_ip="10.32.0.10"

k8s_version="v1.5.1"
etcd_version="v3.1.0"

docker_version="1.12.5"
