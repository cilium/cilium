#!/bin/bash

ID=$1
IFNAME=$2
MAC=$3
IP=$4

echo "Leave EP id=$ID ifname=$IFNAME mac=$MAC ip=$IP"

cd ../common/bpf
./map_ctrl delete "/sys/fs/bpf/tc/globals/cilium_lxc" $ID
tc qdisc delete dev $IFNAME ingress 2> /dev/null
