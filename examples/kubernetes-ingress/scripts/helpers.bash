#!/usr/bin/env bash
#
# Installs, configures and starts etcd, it will use default values from
# ./helpers.bash
# Globals:
#   IPV6_EXT, if set, users IPv6 addresses binaries, otherwise it will use IPv4
#   MASTER_IPV6_PUBLIC, the reachable IPv6 address of kube-apiserver, to be used
#       with IPV6_EXT=1
#   MASTER_IPV4, the reachable IPv4 address of kube-apiserver
#   K8S_CLUSTER_CIDR the cluster cidr to be used in kube-controller-manager
#       cluster-cidr option
#   K8S_NODE_CIDR_MASK_SIZE the node cidr to be used in kube-controller-manager
#       node-cidr-mask-size option
#   K8S_SERVICE_CLUSTER_IP_RANGE the service cluster IP range to be used in
#       kube-controller-manager service-cluster-ip-range option
#   K8S_CLUSTER_DNS_IP the kubedns service IP to be set up in kube-dns service
#       spec file
#   K8S_CLUSTER_API_SERVER_IP the cluster api service IP to be set up in the
#       certificates generated
#######################################

if [[ -n "${IPV6_EXT}" ]]; then
    master_ip=${MASTER_IPV6_PUBLIC:-"FD00::0B"}
    # controllers_ips[0] contains the IP with brackets, to be used with Port in IPv6
    # controllers_ips[1] contains the IP without brackets
    controllers_ips=( "[${master_ip}]" "${master_ip}" )
    dns_probes_ips=( "[::1]" "::1" )
else
    master_ip=${MASTER_IPV4:-"192.168.33.11"}
    controllers_ips=( "${master_ip}" "${master_ip}" )
    dns_probes_ips=( "127.0.0.1" "127.0.0.1" )
fi

kubernetes_master="${controllers_ips[0]}"

# Default values for IPv4
#
# CIDR Range for Pods in cluster.
k8s_cluster_cidr=${K8S_CLUSTER_CIDR:-"10.0.0.0/10"} # 10.0.0.1-10.63.255.254
# Mask size for node cidr in cluster.
k8s_node_cidr_mask_size=${K8S_NODE_CIDR_MASK_SIZE:-"16"} # 1st Node: 10.0.0.1-10.0.255.254, 2nd Node: 10.1.0.1-10.1.255.254...
# CIDR Range for Services in cluster.
k8s_service_cluster_ip_range=${K8S_SERVICE_CLUSTER_IP_RANGE:-"172.20.0.0/24"}
cluster_dns_ip=${K8S_CLUSTER_DNS_IP:-"172.20.0.10"}
cluster_api_server_ip=${K8S_CLUSTER_API_SERVER_IP:-"172.20.0.1"}

# Default values for IPv6
#
# CIDR Range for Pods in cluster.
#k8s_cluster_cidr=${K8S_CLUSTER_CIDR:-"FD02::/96"} # 10.0.0.1-10.63.255.254
# Mask size for node cidr in cluster.
#k8s_node_cidr_mask_size=${K8S_NODE_CIDR_MASK_SIZE:-"112"} # 1st Node: 10.0.0.1-10.0.255.254, 2nd Node: 10.1.0.1-10.1.255.254...
# CIDR Range for Services in cluster.
#k8s_service_cluster_ip_range=${K8S_SERVICE_CLUSTER_IP_RANGE:-"FD03::/112"}
#cluster_dns_ip=${K8S_CLUSTER_DNS_IP:-"FD03::A"}
#cluster_api_server_ip=${K8S_CLUSTER_API_SERVER_IP:-"FD03::1"}

k8s_version="v1.8.1"
etcd_version="v3.2.7"

function restore_flag {
  check_num_params "$#" "2"
  local save=$1
  local flag=$2
  if [[ $save =~ $2 ]]; then
    set -$2
  fi
}

function check_num_params {
  local NUM_PARAMS=$1
  local NUM_EXPECTED_PARAMS=$2
  if [ "$NUM_PARAMS" -ne "$NUM_EXPECTED_PARAMS" ]; then
    echo "${FUNCNAME[ 1 ]}: invalid number of parameters, expected $NUM_EXPECTED_PARAMS parameter(s)"
    exit 1
  fi
}

function log {
  local save=$-
  set +u
  check_num_params "$#" "1"
  message=$1
  local stack
  for (( i=${#FUNCNAME[@]}-1 ; i>0 ; i-- )) ; do
    if [[ "${stack}" == "" ]]; then
      stack="$(basename $0): ${FUNCNAME[i]}"
    else
      stack="$stack/${FUNCNAME[i]}"
    fi
  done
  echo "----- ${stack}: $message"
  restore_flag $save "u"
}
