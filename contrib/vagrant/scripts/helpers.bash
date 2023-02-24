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
#       node-cidr-mask-size-ipv4 option
#   K8S_NODE_CIDR_V6_MASK_SIZE the node cidr to be used in kube-controller-manager
#       node-cidr-mask-size-ipv6 option
#   K8S_SERVICE_CLUSTER_IP_RANGE the service cluster IP range to be used in
#       kube-controller-manager service-cluster-ip-range option
#   K8S_CLUSTER_DNS_IP the kubedns service IP to be set up in kube-dns service
#       spec file
#   K8S_CLUSTER_API_SERVER_IP the cluster api service IP to be set up in the
#       certificates generated
#   K8S_CLUSTER_API_SERVER_IPV6 the cluster api service IPv6 to be set up in the
#       certificates generated
#   WGET, if set https_proxy, it will set https_proxy for the command's wget,
#       otherwise alias for wget
#######################################

if [[ -n "${IPV6_EXT}" ]]; then
    master_ip=${MASTER_IPV6_PUBLIC:-"FD00::0B"}
    # controllers_ips[0] contains the IP with brackets, to be used with Port in IPv6
    # controllers_ips[1] contains the IP without brackets
    controllers_ips=( "[${master_ip}]" "${master_ip}" )
else
    master_ip=${MASTER_IPV4:-"192.168.60.11"}
    controllers_ips=( "${master_ip}" "${master_ip}" )
fi

# container runtime options
case "${RUNTIME}" in
    "crio" | "cri-o")
        container_runtime_name="crio"
        container_runtime_kubelet="remote"
        container_runtime_endpoint="--container-runtime-endpoint=/var/run/crio/crio.sock"
        cgroup_driver='--cgroup-driver=systemd'
        ;;
    *)
        container_runtime_name="containerd"
        container_runtime_kubelet="remote"
        container_runtime_endpoint="--container-runtime-endpoint=unix:///var/run/containerd/containerd.sock"
        cgroup_driver='--cgroup-driver=/system.slice/containerd.service'
        ;;
esac

kubernetes_master="${controllers_ips[0]}"

# Default values for IPv4 and IPv6
#
# CIDR Range for Pods in cluster.
k8s_cluster_cidr=${K8S_CLUSTER_CIDR:-"10.11.0.0/20,FD04::/96"} # 10.11.0.1-10.11.15.255
# Mask size for node cidr in cluster.
k8s_node_cidr_v4_mask_size=${K8S_NODE_CIDR_MASK_SIZE:-"24"} # 1st Node: 10.11.0.1-10.11.0.255, 2nd Node: 10.11.1.1-10.11.1.255..
k8s_node_cidr_v6_mask_size=${K8S_NODE_CIDR_V6_MASK_SIZE:-"112"} # 1st Node: 10.11.0.1-10.11.0.255, 2nd Node: 10.11.1.1-10.11.1.255...
# CIDR Range for Services in cluster.
k8s_service_cluster_ip_range=${K8S_SERVICE_CLUSTER_IP_RANGE:-"172.20.0.0/24,FD03::/112"}
cluster_dns_ip=${K8S_CLUSTER_DNS_IP:-"172.20.0.10"}
cluster_dns_ipv6=${K8S_CLUSTER_DNS_IPV6:-"FD03::A"}
cluster_api_server_ipv4=${K8S_CLUSTER_API_SERVER_IPV4:-"172.20.0.1"}
cluster_api_server_ipv6=${K8S_CLUSTER_API_SERVER_IPV6:-"FD03::1"}

k8s_version="v1.26.0-rc.0"
etcd_version="v3.5.5"

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

function download_to {
    local cache_dir="${1}"
    local component="${2}"
    local url="${3}"

    mkdir -p "${cache_dir}"
    if [ ! -f "${cache_dir}/${component}" ]; then
        log "Downloading ${component}..."

        rm -f "/tmp/${component}"
        ${WGET} -O "/tmp/${component}" -nv "${url}"
        # Hide 'failed to preserve ownership' error
        mv "/tmp/${component}" "${cache_dir}/${component}" 2>/dev/null

        log "Downloading ${component}... Done!"
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
