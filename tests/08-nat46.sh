#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function cleanup {
  log "beginning cleanup for ${TEST_NAME}"
  cilium policy delete --all 2> /dev/null || true
  docker rm -f server client 2> /dev/null || true
  monitor_stop
  log "finished cleanup for ${TEST_NAME}"
}

function finish_test {
  log "beginning finish_test for ${TEST_NAME}"
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
  log "done with finish_test for ${TEST_NAME}"
}

trap finish_test EXIT
cleanup

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"
NETPERF_IMAGE="tgraf/netperf"

monitor_start
logs_clear

create_cilium_docker_network

log "starting containers"
docker run -d -i --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
docker run -d -i --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE
log "done starting containers"

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_IP | awk '{ print $1}')
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_IP4=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.IPAddress }}' server)
SERVER_ID=$(cilium endpoint list | grep $SERVER_IP | awk '{ print $1}')

log "CLIENT_IP=$CLIENT_IP"
log "CLIENT_IP4=$CLIENT_IP4"
log "CLIENT_ID=$CLIENT_ID"
log "SERVER_IP=$SERVER_IP"
log "SERVER_IP4=$SERVER_IP4"
log "SERVER_ID=$SERVER_ID"

wait_for_docker_ipv6_addr client
wait_for_docker_ipv6_addr server

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

log "updating client endpoint configuration: NAT46=true"
cilium endpoint config ${CLIENT_ID} NAT46=true

function connectivity_test64() {
  log "beginning connectivity_test64"
  # ICMPv4 echo request from client to server should succeed
  monitor_clear
  log "pinging NAT64 address of client from host (should work)" 
  docker exec -i client ping6 -c 10 ::FFFF:$SERVER_IP4 || {
    abort "Error: Could not ping nat64 address of client from host"
  }
  log "finished connectivity_test64"
}

connectivity_test64
log "deleting all policies from Cilium"
cilium -D policy delete --all

test_succeeded "${TEST_NAME}"
