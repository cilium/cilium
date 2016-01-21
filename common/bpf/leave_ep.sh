#!/bin/bash

ID=$1

echo "Leave EP id=$ID"

cd ../common/bpf
./map_ctrl delete "/sys/fs/bpf/tc/globals/cilium_lxc" $ID
