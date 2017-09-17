#!/bin/bash

source "./helpers.bash"

set -e

function cleanup {
	gather_files 08-nat46 ${TEST_SUITE}
	cilium policy delete --all 2> /dev/null || true
        docker rm -f server client 2> /dev/null || true
        monitor_stop
}

trap cleanup EXIT
cleanup

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"
NETPERF_IMAGE="tgraf/netperf"

monitor_start
logs_clear

create_cilium_docker_network

docker run -d -i --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -d -i --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_IP | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_IP | awk '{ print $1}')

echo CLIENT_IP=$CLIENT_IP
echo CLIENT_IP4=$CLIENT_IP4
echo CLIENT_ID=$CLIENT_ID
echo SERVER_IP=$SERVER_IP
echo SERVER_IP4=$SERVER_IP4
echo SERVER_ID=$SERVER_ID

wait_for_docker_ipv6_addr client
wait_for_docker_ipv6_addr server

set -x

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${SERVER_LABEL}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"${CLIENT_LABEL}":""}}
	]
    }]
}]
EOF

cilium endpoint config ${CLIENT_ID} NAT46=true

function connectivity_test64() {
        # ICMPv4 echo request from client to server should succeed
        monitor_clear
        docker exec -i client ping6 -c 10 ::FFFF:$SERVER_IP4 || {
                abort "Error: Could not ping nat64 address of client from host"
        }
}

connectivity_test64
cilium -D policy delete --all
