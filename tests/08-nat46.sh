#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"

function cleanup {
        docker rm -f server client 2> /dev/null || true
        monitor_stop
}

trap cleanup EXIT

SERVER_LABEL="io.cilium.server"
CLIENT_LABEL="io.cilium.client"
NETPERF_IMAGE="noironetworks/netperf"

monitor_start

docker network inspect $TEST_NET 2> /dev/null || {
        docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt -ti --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -dt -ti --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

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

# FIXME IPv6 DAD period
sleep 5
set -x

cat <<EOF | cilium -D policy import -
{
        "name": "io.cilium",
        "children": {
                "client": { },
                "server": {
                        "rules": [{
                                "allow": ["../client"]
                        }]
                }

        }
}
EOF

function connectivity_test64() {
        # ICMPv4 echo request from client to server should succeed
        monitor_clear
        docker exec -i client ping6 -c 5 ::FFFF:$SERVER_IP4 || {
                abort "Error: Could not ping nat64 address of client from host"
        }
}

connectivity_test64
cilium -D policy delete io.cilium
