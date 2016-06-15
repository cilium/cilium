#!/bin/bash

set -ex

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"

function cleanup {
	docker rm -f server client 2> /dev/null || true
}

trap cleanup EXIT

function reset_trace {
	if [ -d "/sys/kernel/debug/tracing/" ]; then
		cp /dev/null /sys/kernel/debug/tracing/trace
	fi
}

function abort {
	echo "$*"
	exit 1
}

SERVER_LABEL="io.cilium.server"
CLIENT_LABEL="io.cilium.client"

docker network inspect $TEST_NET || {
	docker network create --ipam-driver cilium --driver cilium $TEST_NET
}

reset_trace
docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

# FIXME IPv6 DAD period
sleep 5

cat <<EOF | cilium -D policy import -
{
        "name": "io.cilium",
        "children": {
		"client": { },
		"server": {
			"rules": [{
				"allow": ["reserved:host", "../client"]
			}]
		}

	}
}
EOF

function policy_test {
	# ICMP echo request client => server should succeed
	docker exec -i client ping6 -c 5 $SERVER_IP || {
		abort "Error: Could not ping server container from client"
	}

	# ICMP echo request host => server should succeed
	ping6 -c 5 $SERVER_IP || {
		abort "Error: Could not ping server container from host"
	}

	# ICMP echo request server => client should not succeed
	docker exec -i server ping6 -c 2 $CLIENT_IP && {
		abort "Error: Unexpected success of ICMP echo request"
	}

	# TCP request to closed port should fail
	docker exec -i client nc $SERVER_IP 777 && {
		abort "Error: Unexpected success of TCP session to port 777"
	}

	# TCP client=>server should succeed
	docker exec -i client netperf -l 3 -t TCP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	# FIXME: Need shorter timeout
	# TCP server=>client should not succeed
	#docker exec -i server netperf -l 3 -t TCP_RR -H $CLIENT_IP && {
	#	abort "Error: Unexpected success of TCP netperf session"
	#}

	# UDP client=server should succeed
	docker exec -i client netperf -l 3 -t UDP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	# FIXME: Need shorter timeout
	# TCP server=>client should not succeed
	#docker exec -i server netperf -l 3 -t UDP_RR -H $CLIENT_IP && {
	#	abort "Error: Unexpected success of UDP netperf session"
	#}
}

policy_test

cilium endpoint config $SERVER_ID DisableConntrack=true

policy_test

cilium -D policy delete io.cilium
