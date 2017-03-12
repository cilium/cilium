#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"
TEST_TIME=30

# Only run these tests if BENCHMARK=1 has been set
if [ -z $BENCHMARK ]; then
	exit 0
fi

function cleanup {
	docker rm -f server client 2> /dev/null || true

	cilium daemon config DropNotification=true Debug=true
}

trap cleanup EXIT

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

docker network inspect $TEST_NET || {
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
HOST_IP=$(echo $SERVER_IP | sed -e 's/:[0-9a-f]\{4\}$/:ffff/')
SERVER_DEV=$(cilium endpoint inspect $SERVER_ID | grep interface-name | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
NODE_MAC=$(cilium endpoint inspect $SERVER_ID | grep node-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
LXC_MAC=$(cilium endpoint inspect $SERVER_ID | grep lxc-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')


# FIXME IPv6 DAD period
sleep 5
set -x

cat <<EOF | cilium -D policy import -
{
        "name": "root",
	"rules": [{
		"coverage": ["${SERVER_LABEL}"],
		"allow": ["reserved:host", "${CLIENT_LABEL}"]
	}]
}
EOF

function perf_test() {
	docker exec -i client netperf -l $TEST_TIME -t TCP_STREAM -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		docker exec -i client netperf -l $TEST_TIME -t TCP_STREAM -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

	docker exec -i client netperf -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		docker exec -i client netperf -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

	docker exec -i client netperf -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP -- -m 256 || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	docker exec -i client super_netperf 8 -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		docker exec -i client super_netperf 8 -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi

	docker exec -i client netperf -l $TEST_TIME -t TCP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	if [ $SERVER_IP4 ]; then
		docker exec -i client netperf -l $TEST_TIME -t TCP_RR -H $SERVER_IP4 || {
			abort "Error: Unable to reach netperf TCP endpoint"
		}
	fi
}

function perf_pktgen() {
	modprobe pktgen

	NUMPKTS=50000000
	FLOWS=16000
	SIZE=256
	DEV=$SERVER_DEV

	CPU_MAX=$(cat /proc/cpuinfo | grep proc | tail -1 | cut -d' ' -f2)

	for processor in $(seq 0 $CPU_MAX)
	do
		PGDEV=/proc/net/pktgen/kpktgend_$processor
		echo "rem_device_all" > $PGDEV
	done

	for processor in $(seq 0 $CPU_MAX)
	do
		PGDEV=/proc/net/pktgen/kpktgend_$processor
		echo "add_device $DEV@$processor" > $PGDEV

		PGDEV=/proc/net/pktgen/$DEV@$processor
                echo "count $NUMPKTS" > $PGDEV
                echo "flag QUEUE_MAP_CPU" > $PGDEV
                echo "pkt_size $SIZE" > $PGDEV
                echo "src_mac $LXC_MAC" > $PGDEV
                echo "dst_mac $NODE_MAC" > $PGDEV
                echo "dst6 $HOST_IP" > $PGDEV
                echo "src6 $SERVER_IP" > $PGDEV
                echo "flows $FLOWS" > $PGDEV
                echo "flowlen 1" > $PGDEV
	done

	PGDEV=/proc/net/pktgen/pgctrl

	echo "start" > $PGDEV

	for processor in $(seq 0 $CPU_MAX)
	do
		cat /proc/net/pktgen/$DEV@$processor
	done
}

cilium daemon config DropNotification=false Debug=false
cilium endpoint config $SERVER_ID DropNotification=false Debug=false
cilium endpoint config $CLIENT_ID DropNotification=false Debug=false
perf_test

cilium endpoint config $SERVER_ID ConntrackAccounting=false
cilium endpoint config $CLIENT_ID ConntrackAccounting=false
perf_test

cilium endpoint config $SERVER_ID Conntrack=false
cilium endpoint config $CLIENT_ID Conntrack=false
perf_test

cilium endpoint config $SERVER_ID Policy=false
cilium endpoint config $CLIENT_ID Policy=false
perf_test

cilium -D policy delete root
