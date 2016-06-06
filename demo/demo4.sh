#!/bin/bash

set -x

sudo docker run -d --name demo3 --net cilium -l io.cilium.server noironetworks/netperf

read -p "$*"
ADDR=$(sudo cilium endpoint list | grep beef| awk '{ print $4}')
sudo docker run --rm -ti --net cilium noironetworks/netperf ping6 -c 2 $ADDR

read -p "$*"
sudo docker run --rm -ti --net cilium noironetworks/netperf netperf -H $ADDR
