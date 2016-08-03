#!/bin/bash

set -e

LIB=$1
RUNDIR=$2
ID=$3
IFNAME=$4

echo "Join EP id=$ID ifname=$IFNAME"

# This directory was created by the daemon and contains the per container header file
DIR="$PWD/$ID"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -O2 -target bpf -I$RUNDIR/globals -I$DIR -I$LIB/include"

clang $CLANG_OPTS -c $LIB/bpf_lxc.c -o $DIR/bpf_lxc.o

tc qdisc replace dev $IFNAME clsact || true
tc filter replace dev $IFNAME ingress bpf da obj $DIR/bpf_lxc.o sec from-container
