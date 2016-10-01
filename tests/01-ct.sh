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

SERVER_LABEL="io.cilium.server"
CLIENT_LABEL="io.cilium.client"

monitor_start

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')

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

	# FIXME: IPv4 host connectivity not working yet

	if [ $BIDIRECTIONAL = 1 ]; then
		# ICMPv6 echo request server => client should not succeed
		monitor_clear
		docker exec -i server ping6 -c 2 $CLIENT_IP && {
			abort "Error: Unexpected success of ICMPv6 echo request"
		}

		if [ $CLIENT_IP4 ]; then
			# ICMPv4 echo request server => client should not succeed
			monitor_clear
			docker exec -i server ping -c 2 $CLIENT_IP4 && {
				abort "Error: Unexpected success of ICMPv4 echo request"
			}
		fi
	fi

	# TCP request to closed port should fail
	monitor_clear
	docker exec -i client nc $SERVER_IP 777 && {
		abort "Error: Unexpected success of TCP IPv6 session to port 777"
	}

	if [ $SERVER_IP4 ]; then
		# TCP request to closed port should fail
		monitor_clear
		docker exec -i client nc $SERVER_IP4 777 && {
			abort "Error: Unexpected success of TCP IPv4 session to port 777"
		}
	fi

	# TCP client=>server should succeed
	monitor_clear
	docker exec -i client netperf -l 3 -t TCP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP IPv6 endpoint"
	}

	if [ $SERVER_IP4 ]; then
		# TCP client=>server should succeed
		monitor_clear
		docker exec -i client netperf -l 3 -t TCP_RR -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP IPv4 endpoint"
		}
	fi

	# FIXME: Need shorter timeout
	# TCP server=>client should not succeed
	#docker exec -i server netperf -l 3 -t TCP_RR -H $CLIENT_IP && {
	#	abort "Error: Unexpected success of TCP netperf session"
	#}

	# UDP client=server should succeed
	monitor_clear
	docker exec -i client netperf -l 3 -t UDP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP IPv6 endpoint"
	}

	if [ $SERVER_IP4 ]; then
		# UDP client=server should succeed
		monitor_clear
		docker exec -i client netperf -l 3 -t UDP_RR -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP IPv4 endpoint"
		}
	fi

	# FIXME: Need shorter timeout
	# TCP server=>client should not succeed
	#docker exec -i server netperf -l 3 -t UDP_RR -H $CLIENT_IP && {
	#	abort "Error: Unexpected success of UDP netperf session"
	#}
}

BIDIRECTIONAL=1
connectivity_test
cilium endpoint config $SERVER_ID Conntrack=false
cilium endpoint config $CLIENT_ID Conntrack=false
BIDIRECTIONAL=0
connectivity_test

cilium -D policy delete io.cilium
