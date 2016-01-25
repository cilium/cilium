#!/bin/bash

set -e

MAP="/sys/fs/bpf/tc/globals/cilium_lxc"

# Enable JIT
echo 1 > /proc/sys/net/core/bpf_jit_enable

cd ../common/bpf
mount bpffs /sys/fs/bpf/ -t bpf || true

mkdir -p $(dirname $MAP)

if [ ! -f "$MAP" ]; then
	./map_ctrl create $MAP
fi
