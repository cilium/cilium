#!/usr/bin/env bash

if [ -n "${IPV4}" ]; then
    ip=$(ip -4 a show cilium_host scope global | grep inet | awk '{print $2}' | sed 's/\/.*//')
    if [ -z "${ip}" ]; then
        ip=$(grep Host-IPv4 /var/run/cilium/globals/node_config.h | awk '{print $3}')
    fi
    if [ -z "$ip" ]; then
        echo "Unable to derive IPv4 address, please edit env-kube.sh manually"
        return 1
    fi
else
    ip=$(ip -6 a show cilium_host scope global | grep inet6 | awk '{print $2}' | sed 's/\/.*//')
    if [ -z "$ip" ]; then
        ip=$(grep Host-IPv6 /var/run/cilium/globals/node_config.h | awk '{print $3}')
    fi

    if [ -z "$ip" ]; then
        echo "Unable to derive IPv6 address, please edit env-kube.sh manually"
        return 1
    fi
fi

# Edit manually here and assign local Ipv6 address if needed
# ip6=dead::

dns_domain="cilium-test"
## Don't change anything bellow this line ##
## unless you know what you're doing      ##

export API_HOST_IP="${ip}"

if [ -n "${IPV4}" ]; then
    export API_HOST="${API_HOST_IP}"
    export ETCD_HOST="${ip}"
    export SERVICE_CLUSTER_IP_RANGE="10.255.0.0/16"
    export KUBE_DNS_SERVER_IP="10.255.255.254"
else
    export API_HOST="[${API_HOST_IP}]"
    export ETCD_HOST="[${ip}]"
    export SERVICE_CLUSTER_IP_RANGE="f00d:1::/112"
    export KUBE_DNS_SERVER_IP="f00d:1::fffe"
fi

export KUBE_ENABLE_CLUSTER_DNS=true
export KUBE_DNS_NAME="${dns_domain}"
export KUBELET_HOST="${ip}"
export NET_PLUGIN="cni"
export NET_PLUGIN_DIR="/etc/cni/net.d"
export API_PORT="8080"
export KUBE_OS_DISTRIBUTION="debian"
export RUNTIME_CONFIG="extensions/v1beta1,extensions/v1beta1/networkpolicies"
export kubectl="/home/vagrant/kubernetes/cluster/kubectl.sh -s ${API_HOST}:${API_PORT}"

# Debugging variables
export LOG_LEVEL=5
# etcd log directory
export ARTIFACTS_DIR="/tmp"
