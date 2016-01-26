#!/bin/bash

set -e

MAP="/sys/fs/bpf/tc/globals/cilium_lxc"

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

cd ../common/bpf

ip link del cilium_vxlan 2> /dev/null || true
ip link add cilium_vxlan type vxlan external
ip link set cilium_vxlan up

tc qdisc add dev cilium_vxlan ingress
tc filter add dev cilium_vxlan parent ffff: bpf da obj lxc_bpf.o sec from-overlay

mount bpffs /sys/fs/bpf/ -t bpf || true

mkdir -p $(dirname $MAP)

if [ ! -f "$MAP" ]; then
	./map_ctrl create $MAP
fi
