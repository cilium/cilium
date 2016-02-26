#!/bin/bash

set -ex

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"

function cleanup {
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

docker network inspect $TEST_NET || {
	docker network create --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server $NETPERF_IMAGE

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)

docker run --rm -i --net=$TEST_NET --name client $NETPERF_IMAGE ping6 -c 5 $SERVER_IP || {
	echo "Error: Could not reach server container"
	exit 1
}

#docker run -it --net=$TEST_NET --name netperf $NETPERF_IMAGE netperf -l 10 -i 10 -I 95,1 -c -j -H $SERVER_IP -t OMNI -- -D  -T tcp -O THROUGHPUT,THROUGHPUT_UNITS,STDDEV_LATENCY,LOCAL_CPU_UTIL

