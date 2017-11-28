#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

NETPERF_IMAGE="tgraf/netperf"
TEST_TIME=30

logs_clear

# Only run these tests if BENCHMARK=1 has been set
if [ -z $BENCHMARK ]; then
  echo "Skipping test, not in benchmark mode."
  echo "Run with BENCHMARK=1 to enable this test"
  exit 0
fi

function cleanup {
  docker rm -f server client 2> /dev/null || true
  cilium config DropNotification=true Debug=true
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

cilium config DropNotification=true TraceNotification=true Debug=true

trap finish_test EXIT

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

create_cilium_docker_network

docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

until [ -n "$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')" ]; do
  echo "Waiting for client endpoint to have an identity"
done
until [ -n "$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')" ]; do
  echo "Waiting for server endpoint to have an identity"
done

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_LABEL | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_LABEL | awk '{ print $1}')
HOST_IP=$(echo $SERVER_IP | sed -e 's/:[0-9a-f]\{4\}$/:ffff/')
SERVER_DEV=$(cilium endpoint get $SERVER_ID | grep interface-name | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
NODE_MAC=$(cilium endpoint get $SERVER_ID | grep host-mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')
LXC_MAC=$(cilium endpoint get $SERVER_ID | grep mac | awk '{print $2}' | sed 's/"//g' | sed 's/,$//')


wait_for_docker_ipv6_addr client
wait_for_docker_ipv6_addr server

cat <<EOF | policy_import_and_wait -
[{
    "endpointSelector": {"matchLabels":{"${SERVER_LABEL}":""}},
    "ingress": [{
        "fromEndpoints": [
	    {"matchLabels":{"reserved:host":""}},
	    {"matchLabels":{"${CLIENT_LABEL}":""}}
	]
    }]
}]
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

cilium config DropNotification=false TraceNotification=false Debug=false
cilium endpoint config $SERVER_ID DropNotification=false TraceNotification=false Debug=false
cilium endpoint config $CLIENT_ID DropNotification=false TraceNotification=false Debug=false
perf_test

cilium endpoint config $SERVER_ID ConntrackAccounting=false
cilium endpoint config $CLIENT_ID ConntrackAccounting=false
perf_test

cilium endpoint config $SERVER_ID Conntrack=false
cilium endpoint config $CLIENT_ID Conntrack=false
perf_test

cilium endpoint config $SERVER_ID IngressPolicy=false
cilium endpoint config $SERVER_ID EgressPolicy=false
cilium endpoint config $CLIENT_ID IngressPolicy=false
cilium endpoint config $CLIENT_ID EgressPolicy=false
perf_test

cilium policy delete --all
test_succeeded "${TEST_NAME}"
