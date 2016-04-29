#!/usr/bin/env bash

ip=$(ip -6 a show cilium_host scope global | grep inet6 | awk '{print $2}' | sed 's/\/.*//')
if [ -z "$ip" ]; then
    ip=$(grep Host-IP /var/run/cilium/globals/node_config.h | awk '{print $3}')
fi

if [ -z "$ip" ]; then
    echo "Unable to derive IPv6 address, please edit env-kube.sh manually"
    return 1
fi

# Edit manually here and assign local Ipv6 address if needed
# ip=dead::

dns_domain="cilium-test"
## Don't change anything bellow this line ##
## unless you know what you're doing      ##
export NET_PLUGIN=cni
export ETCD_HOST="[${ip}]"
export ENABLE_DNS=true
export DNS_SERVER_IP="${ip}"
export DNS_DOMAIN="${dns_domain}"
export NODE_IP="${ip}"
#export LOG_LEVEL=5
