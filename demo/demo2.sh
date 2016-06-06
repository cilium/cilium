#!/bin/bash

set -x

sudo docker run -d --name demo1 --net cilium -l io.cilium.server noironetworks/netperf

sleep 2
sudo cilium endpoint list

read -p "$*"
ADDR=$(sudo cilium endpoint list | grep beef| awk '{ print $4}')
ping6 -c 4 $ADDR

read -p "$*"
ID=$(sudo cilium endpoint list | grep beef| awk '{ print $1}')
cat /var/run/cilium/$ID/lxc_config.h

read -p "$*"
IPV4="$(grep IPv4 /var/run/cilium/$ID/lxc_config.h | awk '{print $4}')"
ping -c 2 $IPV4

read -p "$*"
sudo cilium endpoint nat46 enable $ID

read -p "$*"
ping -c 10 $IPV4

sudo docker rm -f demo1
