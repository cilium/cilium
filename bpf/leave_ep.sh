#!/bin/bash

LIB=$1
ID=$2

echo "Leave EP id=$ID"

$LIB/map_ctrl delete "/sys/fs/bpf/tc/globals/cilium_lxc" $ID
