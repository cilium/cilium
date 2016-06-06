#!/bin/bash

set -x

sudo docker run -d --name demo3 --net cilium -l io.cilium.server noironetworks/netperf

read -p "$*"
ID=$(sudo cilium endpoint list | grep beef| awk '{ print $1}')
ADDR=$(sudo cilium endpoint list | grep beef| awk '{ print $4}')
ping6 -c 4 $ADDR

read -p "$*"
sudo cilium policy allowed -s unknown_label -d io.cilium.server

read -p "$*"
sudo docker run --rm -ti --net cilium noironetworks/nettools ping6 -c 4 $ADDR

read -p "$*"
sudo cilium policy allowed -s io.cilium.client -d io.cilium.server

read -p "$*"
sudo docker run --rm -ti --net cilium -l io.cilium.client noironetworks/nettools ping6 -c 4 $ADDR

read -p "$*"
sudo docker run --rm -ti --net cilium -l io.cilium.client noironetworks/netperf super_netperf 4 -H $ADDR -l 30

read -p "$*"
sudo docker rm -f demo3
