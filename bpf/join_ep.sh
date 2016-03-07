#!/bin/bash

set -e

LIB=$1
ID=$2
IFNAME=$3

echo "Join EP id=$ID ifname=$IFNAME"

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/$ID"

# Temporary fix until clang is properly installed and available in default PATH
export PATH="/usr/local/clang+llvm-3.7.1-x86_64-linux-gnu-ubuntu-14.04/bin/:$PATH"

clang -O2 -target bpf -c $LIB/bpf_lxc.c -I/var/run/cilium/globals -I$DIR/$ID -I$DIR/globals -o $DIR/bpf_lxc.o
clang -O2 -target bpf -c $LIB/bpf_policy.c -I/var/run/cilium/globals -I$DIR/$ID -I$DIR/globals -o $DIR/bpf_policy.o

#tc qdisc add dev $IFNAME root handle eeee: prio bands 3
tc qdisc add dev $IFNAME clsact

tc filter add dev $IFNAME ingress bpf da obj $DIR/bpf_lxc.o sec from-container
# FIXME: Load bpf_policy
