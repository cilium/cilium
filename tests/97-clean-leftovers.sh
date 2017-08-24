#!/usr/bin/env bash

source "./helpers.bash"

NETPERF_IMAGE="tgraf/netperf"

create_cilium_docker_network

set -x

docker run -dt --net=$TEST_NET --name server -l id.test $NETPERF_IMAGE

prev_ifs=$(sudo ip link show | wc -l)

sudo ip link add lxc12345 type veth peer name tmp54321

if [ $? -ne 0 ]; then abort "unable to add a test veth interface" ; fi

sudo service cilium restart

wait_for_cilium_status

sudo ip link show lxc12345

if [ $? -eq 0 ]; then abort "leftover interface were not properly clean up" ; fi

cur_ifs=$(sudo ip link show | wc -l)

if [ ${prev_ifs} -ne ${cur_ifs} ]; then abort "Some network interfaces were accidentally removed!" ; fi
