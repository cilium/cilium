#!/bin/bash

ID=$1
IFNAME=$2
MAC=$3
IP=$4

tc qdisc delete dev $IFNAME ingress 2> /dev/null
