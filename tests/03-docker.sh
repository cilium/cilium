#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"

function cleanup {
	docker rm -f server client 2> /dev/null || true
	monitor_stop
}

trap cleanup EXIT

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

sudo cilium -D policy import ./policy

docker network inspect $TEST_NET || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

monitor_start

set -x

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)

monitor_clear
docker run --rm -i --net=$TEST_NET --name client -l $CLIENT_LABEL noironetworks/nettools sh -c "sleep 5s && ping6 -c 5 $SERVER_IP" || {
	abort "Error: Could not ping server container"
}

#monitor_clear
#docker run --rm -i --net=$TEST_NET --name client -l $CLIENT_LABEL noironetworks/nettools sh -c "sleep 5s && tracepath6 $SERVER_IP" || {
#	abort "Error: Could not traceroute to server"
#}

monitor_clear
docker run --rm -i --net=$TEST_NET --name netperf -l $CLIENT_LABEL $NETPERF_IMAGE sh -c "sleep 5s && netperf -c -C -H $SERVER_IP" || {
	abort "Error: Could not netperf to server"
}

monitor_clear
docker run --rm -i --net=$TEST_NET --name netperf -l $CLIENT_LABEL $NETPERF_IMAGE sh -c "sleep 5s && netperf -c -C -t TCP_SENDFILE -H $SERVER_IP" || {
	abort "Error: Could not netperf to server"
}

monitor_clear
docker run --rm -i --net=$TEST_NET --name netperf -l $CLIENT_LABEL $NETPERF_IMAGE sh -c "sleep 5s && super_netperf 10 -c -C -t TCP_SENDFILE -H $SERVER_IP" || {
	abort "Error: Could not netperf to server"
}

monitor_clear
ping6 -c 5 "$SERVER_IP" || {
	abort "Error: Could not ping server container from host"
}

sudo cilium -D policy delete root
