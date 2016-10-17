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

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

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

function int_to_ip4 {
echo -n $(($(($(($((${1}/256))/256))/256))%256)).
echo -n $(($(($((${1}/256))/256))%256)).
echo -n $(($((${1}/256))%256)).
echo $((${1}%256))
}

# 10.1 prefix 10 * 256*256*256 + 1 *  256*256
IP64_PREFIX=167837696
CLIENT_IP64=$(int_to_ip4 $((IP64_PREFIX+CLIENT_ID)))
SERVER_IP64=$(int_to_ip4 $((IP64_PREFIX+SERVER_ID)))

# FIXME IPv6 DAD period
sleep 5
set -x

cat <<EOF | cilium -D policy import -
{
        "name": "io.cilium",
        "children": {
                "client": {
                        "rules": [{
                                "allow": ["reserved:host"]
                        }]
                },
                "server": {
                        "rules": [{
                                "allow": ["reserved:host", "../client"]
                        }]
                }

        }
}
EOF

function connectivity_test() {
        # ICMPv6 echo request client => server should succeed
        monitor_clear
        docker exec -i client ping6 -c 5 $SERVER_IP || {
                abort "Error: Could not ping server container from client"
        }

        if [ $SERVER_IP4 ]; then
                # ICMPv4 echo request client => server should succeed
                monitor_clear
                docker exec -i client ping -c 5 $SERVER_IP4 || {
                        abort "Error: Could not ping server container from client"
                }
        fi

        # ICMPv6 echo request host => client should succeed
        monitor_clear
        ping6 -c 5 $CLIENT_IP || {
                abort "Error: Could not ping server container from host"
        }

        if [ $CLIENT_IP4 ]; then
                # ICMPv4 echo request host => client should succeed
                monitor_clear
                ping -c 5 $CLIENT_IP4 || {
                        abort "Error: Could not ping server container from host"
                }
        fi

        # ICMPv6 echo request host => server should succeed
        monitor_clear
        ping6 -c 5 $SERVER_IP || {
                abort "Error: Could not ping server container from host"
        }

        if [ $SERVER_IP4 ]; then
                # ICMPv4 echo request host => server should succeed
                monitor_clear
                ping -c 5 $SERVER_IP4 || {
                        abort "Error: Could not ping server container from host"
                }
        fi

}

function connectivity_test64() {
        # ICMPv4 echo request host => client64 should succeed
        monitor_clear
        ping -c 5 $CLIENT_IP64 || {
                abort "Error: Could not ping nat64 address of client from host"
        }

        # ICMPv4 echo request host => server64 should succeed
        monitor_clear
        ping -c 5 $SERVER_IP64 || {
                abort "Error: Could not ping nat64 address of server from host"
        }
}

connectivity_test
connectivity_test64

cilium -D policy delete io.cilium
