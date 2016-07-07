#!/bin/bash

set -ex

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"

function cleanup {
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

function abort {
	echo "$*"
	exit 1
}

SERVER_LABEL="io.cilium.test.server"
CLIENT_LABEL="io.cilium.test.client"

sudo cilium -D policy import ./policy

docker network inspect $TEST_NET || {
	docker network create --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)

docker run --rm -i --net=$TEST_NET --name client -l $CLIENT_LABEL noironetworks/nettools sh -c "sleep 5s && ping6 -c 5 $SERVER_IP" || {
	abort "Error: Could not ping server container"
}

#docker run --rm -i --net=$TEST_NET --name client -l $CLIENT_LABEL noironetworks/nettools sh -c "sleep 5s && tracepath6 $SERVER_IP" || {
#	abort "Error: Could not traceroute to server"
#}

docker run --rm -i --net=$TEST_NET --name netperf -l $CLIENT_LABEL $NETPERF_IMAGE sh -c "sleep 5s && netperf -c -C -H $SERVER_IP" || {
	abort "Error: Could not netperf to server"
}

docker run --rm -i --net=$TEST_NET --name netperf -l $CLIENT_LABEL $NETPERF_IMAGE sh -c "sleep 5s && netperf -c -C -t TCP_SENDFILE -H $SERVER_IP" || {
	abort "Error: Could not netperf to server"
}

docker run --rm -i --net=$TEST_NET --name netperf -l $CLIENT_LABEL $NETPERF_IMAGE sh -c "sleep 5s && super_netperf 10 -c -C -t TCP_SENDFILE -H $SERVER_IP" || {
	abort "Error: Could not netperf to server"
}

ping6 -c 5 "$SERVER_IP" || {
	abort "Error: Could not ping server container from host"
}

sudo cilium -D policy delete io.cilium
