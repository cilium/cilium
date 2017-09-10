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

function cleanup {
  cilium policy delete --all 2> /dev/null || true
  docker rm -f server client 2> /dev/null || true
  monitor_stop
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

logs_clear

trap finish_test EXIT
cleanup

SERVER_LABEL="id.server"
CLIENT_LABEL="id.client"

policy_import_and_wait ./policy

create_cilium_docker_network

monitor_start

log "running server container"
docker run -dt --net=$TEST_NET --name server -l $SERVER_LABEL $NETPERF_IMAGE
log "running client container"
docker run -dt --net=$TEST_NET --name client -l $CLIENT_LABEL $NETPERF_IMAGE

wait_for_endpoints 2

SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)

monitor_clear
log "ping6 to server from client (should succeed)"
docker exec -i client ping6 -c 5 $SERVER_IP || {
  abort "Error: Could not ping server container"
}

monitor_clear
log "netperf to server from client (should succeed)"
docker exec -i client netperf -c -C -H $SERVER_IP || {
  abort "Error: Could not netperf to server"
}

monitor_clear
log "netperf to server from client (should succeed)"
docker exec -i client netperf -c -C -t TCP_SENDFILE -H $SERVER_IP || {
  abort "Error: Could not netperf to server"
}

monitor_clear
log "super_netperf to server from client (should succeed)"
docker exec -i client super_netperf 10 -c -C -t TCP_SENDFILE -H $SERVER_IP || {
  abort "Error: Could not netperf to server"
}

monitor_clear
log "pinging server from host (should succeed)"
ping6 -c 5 "$SERVER_IP" || {
  abort "Error: Could not ping server container from host"
}

log "deleting policy id=server from Cilium"
cilium policy delete id=server

# FIXME Disabled for now as we don't have a reliable way to wait for the async
# removel of the CT entries
#wait_for_endpoints 2
#
#ping6 -c 2 "$SERVER_IP" && {
#	abort "Error: Unexpected connectivity between host and server after policy removed"
#}

log "deleting all policies in Cilium"
cilium policy delete --all

test_succeeded "${TEST_NAME}"
