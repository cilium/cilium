#!/bin/bash

set -ex

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"
TEST_TIME=30

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
HOST_IP=$(echo $SERVER_IP | sed -e 's/:[0-9a-f]\{4\}$/:ffff/')
SERVER_DEV=$(cilium endpoint inspect $SERVER_ID | grep interface-name | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
NODE_MAC=$(cilium endpoint inspect $SERVER_ID | grep node-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
LXC_MAC=$(cilium endpoint inspect $SERVER_ID | grep lxc-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')

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

function perf_test() {
	docker exec -i client netperf -l $TEST_TIME -t TCP_STREAM -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	docker exec -i client netperf -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	docker exec -i client netperf -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP -- -m 256 || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	docker exec -i client super_netperf 8 -l $TEST_TIME -t TCP_SENDFILE -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}

	docker exec -i client netperf -l $TEST_TIME -t TCP_RR -H $SERVER_IP || {
		abort "Error: Unable to reach netperf TCP endpoint"
	}
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

cilium endpoint config $SERVER_ID DropNotification=false
cilium endpoint config $SERVER_ID Debug=false
cilium endpoint config $CLIENT_ID DropNotification=false
cilium endpoint config $CLIENT_ID Debug=false
perf_test

cilium endpoint config $SERVER_ID DisableConntrack=true
cilium endpoint config $CLIENT_ID DisableConntrack=true
perf_test

cilium endpoint config $SERVER_ID DisablePolicy=true
cilium endpoint config $CLIENT_ID DisablePolicy=true
perf_test

cilium -D policy delete io.cilium
