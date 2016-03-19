#!/usr/bin/env bash
ip="beef::dead:fffe"
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
