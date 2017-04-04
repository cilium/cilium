#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"

function cleanup {
	docker rm -f server client httpd1 httpd2 curl 2> /dev/null || true
	monitor_stop
}

trap cleanup EXIT

cleanup
monitor_start

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

docker run -dt --net=$TEST_NET --name server -l id.server tgraf/netperf
docker run -dt --net=$TEST_NET --name httpd1 -l id.httpd httpd
docker run -dt --net=$TEST_NET --name httpd2 -l id.httpd_deny httpd
docker run -dt --net=$TEST_NET --name client -l id.client tgraf/netperf
docker run -dt --net=$TEST_NET --name curl   -l id.curl tgraf/netperf

until [ "$(cilium endpoint list | grep ready -c)" -eq "5" ]; do
    echo "Waiting for all endpoints to be ready"
    sleep 2s
done

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
CLIENT_ID=$(cilium endpoint list | grep id.client | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
SERVER_ID=$(cilium endpoint list | grep id.server | awk '{ print $1}')
HTTPD1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' httpd1)
HTTPD1_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' httpd1)
HTTPD2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' httpd2)
HTTPD2_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' httpd2)

set -x

cilium endpoint list

cat <<EOF | cilium -D policy import -
{
        "name": "root",
	"rules": [{
		"coverage": ["id.curl"],
		"l4": [{
			"out-ports": [{"port": 80, "protocol": "tcp"}]
		}]
	},{
		"coverage": ["id.server"],
		"allow": ["reserved:host", "id.client"]
	},{
		"coverage": ["id.httpd"],
		"allow": ["id.curl"]
	},{
		"coverage": ["id.httpd"],
		"l4": [{
			"in-ports": [{"port": 80, "protocol": "tcp"}]
		}]
	},{
		"coverage": ["id.httpd_deny"],
		"allow": ["id.curl"]
	},{
		"coverage": ["id.httpd_deny"],
		"l4": [{
			"in-ports": [{"port": 9090, "protocol": "tcp"}]
		}]
	}]
}
EOF

until [ "$(cilium endpoint list | grep ready -c)" -eq "5" ]; do
    echo "Waiting for all endpoints to be ready"
    sleep 2s
done

function connectivity_test() {
	monitor_clear
	docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://[$HTTPD1_IP]:80" || {
		abort "Error: Could not reach httpd1 on port 80"
	}

	monitor_clear
	docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://$HTTPD1_IP4:80" || {
		abort "Error: Could not reach httpd1 on port 80"
	}

	monitor_clear
	docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://[$HTTPD2_IP]:80" && {
		abort "Error: Unexpected success reaching httpd2 on port 80"
	}

	monitor_clear
	docker exec -i curl bash -c "curl --connect-timeout 5 -XGET http://$HTTPD2_IP4:80" && {
		abort "Error: Unexpected success reaching httpd2 on port 80"
	}

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
	docker exec -i client nc -w 5 $SERVER_IP 777 && {
		abort "Error: Unexpected success of TCP IPv6 session to port 777"
	}

	if [ $SERVER_IP4 ]; then
		# TCP request to closed port should fail
		monitor_clear
		docker exec -i client nc -w 5 $SERVER_IP4 777 && {
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
until [ "$(cilium endpoint list | grep ready -c)" -eq "5" ]; do
    echo "Waiting for all endpoints to be ready"
    sleep 2s
done
BIDIRECTIONAL=0
connectivity_test

cilium -D policy delete root
