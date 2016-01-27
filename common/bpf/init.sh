#!/bin/bash

ADDR=$1
MODE=$2

set -e

MAP="/sys/fs/bpf/tc/globals/cilium_lxc"

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/globals"

cd ../common/bpf

# Temporary fix until clang is properly installed and available in default PATH
export PATH="/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin/:$PATH"

if [ "$MODE" = "vxlan" ]; then
	ip link del cilium_vxlan 2> /dev/null || true
	ip link add cilium_vxlan type vxlan external
	ip link set cilium_vxlan up

	clang -O2 -emit-llvm -c bpf_overlay.c -I$DIR -I. -o - | llc -march=bpf -filetype=obj -o $DIR/bpf_overlay.o

	tc qdisc add dev cilium_vxlan ingress
	tc filter add dev cilium_vxlan parent ffff: bpf da obj $DIR/bpf_overlay.o sec from-overlay
elif [ "$MODE" = "direct" ]; then
	DEV=$3

	if [ -z "$DEV" ]; then
		echo "No device specified for direct mode, ignoring..."
	else
		ip addr del $ADDR/80 dev $DEV 2> /dev/null || true
		ip addr add $ADDR/80 dev $DEV

		sysctl -w net.ipv6.conf.all.forwarding=1

		clang -O2 -emit-llvm -c bpf_netdev.c -I$DIR -I. -o - | llc -march=bpf -filetype=obj -o $DIR/bpf_netdev.o

		tc qdisc del dev $DEV ingress 2> /dev/null || true
		tc qdisc add dev $DEV ingress
		tc filter add dev $DEV parent ffff: bpf da obj $DIR/bpf_netdev.o sec from-netdev
	fi
else
	echo "Warning: unknown mode: \"$MODE\""
	exit
fi

mount bpffs /sys/fs/bpf/ -t bpf || true

mkdir -p $(dirname $MAP)

if [ ! -f "$MAP" ]; then
	./map_ctrl create $MAP
fi
