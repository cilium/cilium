#!/bin/bash

source "./helpers.bash"

set -e

NETPERF_IMAGE="tgraf/netperf"

function cleanup {
	gather_files 03-docker ${TEST_SUITE}
	cilium policy delete --all 2> /dev/null || true
	docker rm -f server client 2> /dev/null || true
	monitor_stop
}

logs_clear

trap cleanup EXIT
cleanup

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

policy_import_and_wait ./policy

create_cilium_docker_network

monitor_start

set -x

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

wait_for_endpoints 2

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)

monitor_clear
docker exec -i client ping6 -c 5 $SERVER_IP || {
	abort "Error: Could not ping server container"
}

monitor_clear
docker exec -i client netperf -c -C -H $SERVER_IP || {
	abort "Error: Could not netperf to server"
}

monitor_clear
docker exec -i client netperf -c -C -t TCP_SENDFILE -H $SERVER_IP || {
	abort "Error: Could not netperf to server"
}

monitor_clear
docker exec -i client super_netperf 10 -c -C -t TCP_SENDFILE -H $SERVER_IP || {
	abort "Error: Could not netperf to server"
}

monitor_clear
ping6 -c 5 "$SERVER_IP" || {
	abort "Error: Could not ping server container from host"
}

cilium policy delete id=server

# FIXME Disabled for now as we don't have a reliable way to wait for the async
# removel of the CT entries
#wait_for_endpoints 2
#
#ping6 -c 2 "$SERVER_IP" && {
#	abort "Error: Unexpected connectivity between host and server after policy removed"
#}

cilium policy delete --all
