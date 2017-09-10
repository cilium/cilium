#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME="97-clean-leftovers"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

NETPERF_IMAGE="tgraf/netperf"

create_cilium_docker_network

docker run -dt --net=$TEST_NET --name server -l id.test $NETPERF_IMAGE

prev_ifs=$(sudo ip link show | wc -l)

sudo ip link add lxc12345 type veth peer name tmp54321

if [ $? -ne 0 ]; then abort "unable to add a test veth interface" ; fi

sudo service cilium restart

wait_for_cilium_status

set +e
sudo ip link show lxc12345
if [ $? -eq 0 ]; then
  abort "leftover interface were not properly cleaned up"
fi
set -e

cur_ifs=$(sudo ip link show | wc -l)

if [ ${prev_ifs} -ne ${cur_ifs} ]; then abort "Some network interfaces were accidentally removed!" ; fi

test_succeeded "${TEST_NAME}"
