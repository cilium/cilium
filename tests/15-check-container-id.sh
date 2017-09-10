#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

CLIENT_LABEL="id.client"
SERVER_LABEL="id.server"

function cleanup {
  log "beginning cleanup for ${TEST_NAME}"
  log "removing containers server and client"
  docker rm -f server client 2> /dev/null || true
  log "finished cleanup for ${TEST_NAME}"
}

function setup {
  log "beginning setup of ${TEST_NAME}"
  logs_clear
  monitor_start
  log "monitor is logging at $DUMP_FILE"
  remove_cilium_docker_network
  create_cilium_docker_network
  log "setting Cilium configuration: PolicyEnforcement=always"
  cilium config PolicyEnforcement=always
  log "finished setup for ${TEST_NAME}"
}

trap cleanup EXIT

setup

log "starting server container"
docker run -d --net cilium --name server -l ${SERVER_LABEL} tgraf/netperf

log "output of \"cilium endpoint list\""
cilium endpoint list

docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server
SERVER_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server)
SERVER_ID=$(cilium endpoint list | grep ${SERVER_LABEL} | awk '{ print $1}')

log "pinging server at IP ${SERVER_IP}"
ping6 -c 1 ${SERVER_IP} || true

docker run -d --net cilium --name client -l ${CLIENT_LABEL} tgraf/netperf

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep ${CLIENT_LABEL} | awk '{ print $1}')

log "output of \"cilium endpoint list\""
cilium endpoint list

log "pinging server at IP ${SERVER_IP} from client"
docker exec -ti client ping6 -c 1 ${SERVER_IP} || true

log "output of \"sudo cilium bpf policy list ${SERVER_ID}\""
sudo cilium bpf policy list ${SERVER_ID}

log "pinging client  at IP ${CLIENT_IP} from server"
docker exec -ti server ping6 -c 1 ${CLIENT_IP} || true

log "setting configuration for endpoint ${CLIENT_ID} Conntrack=false"
cilium endpoint config ${CLIENT_ID} Conntrack=false
log "setting configuration for endpoint ${SERVER_ID} Conntrack=false"
cilium endpoint config ${SERVER_ID} Conntrack=false

log "pinging client  at IP ${CLIENT_IP} from server"
docker exec -ti server ping6 -c 1 ${CLIENT_IP} || true
log "pinging server at IP ${SERVER_IP} from client"
docker exec -ti client ping6 -c 1 ${SERVER_IP} || true

known_ids=(`cilium endpoint list| awk '{ if (NR > 1) print " "$1 }' |tr -d '\n'`)

grep "Attempting local delivery for container id " ${DUMP_FILE} | while read -r entry ; do
  # CPU 01: MARK 0x3de3947b FROM 48896 DEBUG: Attempting local delivery for container id 29381 from seclabel 263
  #                              ^                                                       ^
  # Above is the expected full example output.
  container_id=`echo ${entry} | awk '{ print $14 }'`
  from_id=`echo ${entry} | awk '{ print $5 }'`
  did_match=false

  if [[ "$container_id" == "$from_id" ]]; then
    abort "was not expecting container id ($container_id) to equal from ($from_id)"
  fi

  for id in "${known_ids[@]}"; do
    if [[ "$container_id" == "$id" ]]; then
      did_match=true
      break
    fi
  done

  if ! ${did_match} ; then
    abort "$container_id is not in the known list of ids"
  fi
done

monitor_stop

test_succeeded "${TEST_NAME}"
