#!/bin/bash

LIB=$1
ADDR=$2
MODE=$3

set -e

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

function mac2array()
{
	echo "{ 0x${1//:/, 0x} }"
}

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"

# Temporary fix until clang is properly installed and available in default PATH
export PATH="/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin/:$PATH"

HOST_DEV1="cilium_host"
HOST_DEV2="cilium_net"

ip link del $HOST_DEV1 2> /dev/null || true
ip link add $HOST_DEV1 type veth peer name $HOST_DEV2
ip link set $HOST_DEV1 up
ip link set $HOST_DEV2 up

HOST_IP=$(echo $ADDR | sed 's/:0$/:ffff/')
ip addr del $HOST_IP/128 dev $HOST_DEV1 2> /dev/null || true
ip addr add $HOST_IP/128 dev $HOST_DEV1

ip route add $ADDR/128 dev $HOST_DEV1
ip route add $ADDR/112 via $ADDR

HOST_IDX=$(cat /sys/class/net/${HOST_DEV2}/ifindex)
HOST_MAC=$(ip link show $HOST_DEV1 | grep ether | awk '{print $2}')
HOST_MAC=$(mac2array $HOST_MAC)
echo "#define HOST_IFINDEX $HOST_IDX" >> /var/run/cilium/globals/node_config.h
echo "#define HOST_IFINDEX_MAC { .addr = ${HOST_MAC}}" >> /var/run/cilium/globals/node_config.h

clang -O2 -target bpf -c $LIB/bpf_netdev.c -I$DIR -I. -o bpf_netdev.o

tc qdisc del dev cilium_net clsact 2> /dev/null || true
tc qdisc add dev cilium_net clsact
tc filter add dev cilium_net ingress bpf da obj bpf_netdev.o sec from-netdev

if [ "$MODE" = "vxlan" -o "$MODE" = "geneve" ]; then
	ENCAP_DEV="cilium_${MODE}"
	ip link del $ENCAP_DEV 2> /dev/null || true
	ip link add $ENCAP_DEV type $MODE external
	ip link set $ENCAP_DEV up

	ENCAP_IDX=$(cat /sys/class/net/${ENCAP_DEV}/ifindex)
	sed '/ENCAP_IFINDEX/d' /var/run/cilium/globals/node_config.h
	echo "#define ENCAP_IFINDEX $ENCAP_IDX" >> /var/run/cilium/globals/node_config.h

	clang -O2 -target bpf -c $LIB/bpf_overlay.c -I$DIR -I. -o bpf_overlay.o

	tc qdisc add dev $ENCAP_DEV clsact
	tc filter add dev $ENCAP_DEV ingress bpf da obj bpf_overlay.o sec from-overlay
elif [ "$MODE" = "direct" ]; then
	DEV=$4

	if [ -z "$DEV" ]; then
		echo "No device specified for direct mode, ignoring..."
	else
		sysctl -w net.ipv6.conf.all.forwarding=1

		tc qdisc del dev $DEV clsact 2> /dev/null || true
		tc qdisc add dev $DEV clsact

		tc filter add dev $DEV ingress bpf da obj bpf_netdev.o sec from-netdev
	fi
else
	echo "Warning: unknown mode: \"$MODE\""
	exit
fi

mount bpffs /sys/fs/bpf/ -t bpf || true
