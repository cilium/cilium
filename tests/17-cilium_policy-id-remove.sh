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
  log "beginning cleanup for $0"
  log "removing containerA and containerB"
  docker rm -f containerA containerB 2> /dev/null || true
  log "removing docker network $TEST_NET"
  remove_cilium_docker_network
  log "cleanup done for $0"
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

log "running cleanup before ${TEST_NAME} begins"
cleanup
logs_clear

create_cilium_docker_network

log "creating containerA"
docker run -dt --net=$TEST_NET --name containerA -l id.a tgraf/netperf
log "done creating containerA"
log "creating containerB"
docker run -dt --net=$TEST_NET --name containerB -l id.b tgraf/netperf
log "done creating containerB"

known_endpoints=`cilium endpoint list|awk 'NR>2 { print $1 }'`

# Sanity check
for ep in $known_endpoints; do
  log "checking that endpoint policy map exists for endpoint $ep"
  ep_policy_map="/sys/fs/bpf/tc/globals/cilium_policy_$ep"
  if [ ! -f $ep_policy_map ]; then
    abort "No such file $ep_policy_map"
  fi
done

log "before removal"
log "endpoint list: `cilium endpoint list`"
log "docker: `docker ps`"

log "removing containerA and containerB"
docker rm -f containerA containerB

log "after removal"
log "endpoint list: `cilium endpoint list`"
log "docker: `docker ps`"

# In the unlikely case endpoint deletion should take longer than expected, wait.
wait_for_endpoints_deletion

# There should only be one cilium_policy file after the containers are gone.
# Ignoring the reserved files.
log "checking that only one cilium_policy map exists after containers have been removed"
actual=`find /sys/fs/bpf/tc/globals/cilium_policy*|grep -v reserved`
expected="/sys/fs/bpf/tc/globals/cilium_policy"
if [ "$actual" != "$expected" ]; then
  abort "want $expected got $actual"
fi

test_succeeded "${TEST_NAME}"
