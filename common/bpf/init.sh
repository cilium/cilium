#!/bin/bash

set -e

MAP="/sys/fs/bpf/tc/globals/cilium_lxc"

cd ../common/bpf
mount bpffs /sys/fs/bpf/ -t bpf || true

mkdir -p $(dirname $MAP)

if [ ! -f "$MAP" ]; then
	./map_ctrl create $MAP
fi
