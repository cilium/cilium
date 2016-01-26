#!/bin/bash

set -e

MAP="/sys/fs/bpf/tc/globals/cilium_lxc"

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

ip link del cilium_vxlan 2> /dev/null || true
ip link add cilium_vxlan type vxlan external

cd ../common/bpf
mount bpffs /sys/fs/bpf/ -t bpf || true

mkdir -p $(dirname $MAP)

if [ ! -f "$MAP" ]; then
	./map_ctrl create $MAP
fi
