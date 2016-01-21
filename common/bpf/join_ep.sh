#!/bin/bash

set -e

ID=$1
IFNAME=$2
MAC=$3
IP=$4

IFINDEX=$(cat /sys/class/net/$IFNAME/ifindex)

echo "Join EP id=$ID ifname=$IFNAME mac=$MAC ip=$IP ifindex=$IFINDEX"

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/$ID"

cd ../common/bpf
./map_ctrl update "/sys/fs/bpf/tc/globals/cilium_lxc" $ID $IFINDEX $MAC $IP

# Temporary fix until clang is properly installed and available in default PATH
export PATH="/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin/:$PATH"

clang -O2 -emit-llvm -c lxc_bpf.c -I$DIR -o - | llc -march=bpf -filetype=obj -o $DIR/bpf.o

# Still need this prio bandaid as we don't have prequeue yet, can become a bottleneck due to locking
#tc qdisc add dev $IFNAME root handle eeee: prio bands 3
tc qdisc add dev $IFNAME ingress

#tc filter add dev dummy1 parent eeee: bpf da obj /tmp/bpf.o sec dummy1-egress
tc filter add dev $IFNAME parent ffff: bpf da obj $DIR/bpf.o sec from-container
