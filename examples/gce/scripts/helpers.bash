#!/usr/bin/env bash

region="europe-west1"
zone="${region}-b"

# CIDR Range for Nodes in cluster.
k8s_cluster_range="172.16.0.0/24"

# Not advised to change the controller's length and worker's length unless you see all
# scripts, they are hardcoded for 3 controllers and 3 workers. Sorry!
controllers_ips=("172.16.0.10" "172.16.0.11" "172.16.0.12")
workers_ips=("172.16.0.20" "172.16.0.21" "172.16.0.22")

# CIDR Range for Pods in cluster.
k8s_cluster_cidr="10.200.0.0/13" # 10.200.0.1-10.207.255.254
# Mask size for node cidr in cluster.
k8s_node_cidr_mask_size="16" # 10.200.0.1-10.200.255.254, 10.201.0.1-10.201.255.254...

# CIDR Range for Services in cluster.
k8s_service_cluster_ip_range="10.32.0.0/24"
k8s_master_service_ip="10.32.0.1"
cluster_dns_ip="10.32.0.10"

k8s_version="v1.5.2"
etcd_version="v3.1.0"

docker_version="1.13.0"
