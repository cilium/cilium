#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

logs_clear

log "starting test ${TEST_NAME}"

CLIENT_LABEL="client"
CONTAINER=monitor_tests

function cleanup {
  log "beginning cleanup for $TEST_NAME"
  remove_all_containers
  remove_cilium_docker_network
  monitor_stop
  log "done with cleanup for $TEST_NAME"
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

function spin_up_container {
  log "starting container $CONTAINER"
  docker run -d --net cilium --name $CONTAINER -l $CLIENT_LABEL tgraf/netperf > /dev/null 2>&1
  log "output of ip -6 address list in container $CONTAINER"
  docker exec -i $CONTAINER ip -6 address list
  log "output of 'ip -6 route list dev cilium0' in container $CONTAINER"
  docker exec -i $CONTAINER ip -6 route list dev cilium0 
  log "done starting container $CONTAINER"
}

function setup {
  cleanup
  create_cilium_docker_network
  logs_clear
  monitor_clear
}

function test_event_types {
  log "event filter"
  cilium config Debug=true DropNotification=true TraceNotification=true

  event_types=( drop debug capture )
  expected_log_entry=( "DROP:" "DEBUG:" "DEBUG:" )

  for ((index=0;index<${#event_types[@]};++index)); do
    log "starting ${event_types[index]}"
    setup
    monitor_start --type ${event_types[index]}
    spin_up_container
    wait_for_log_entries 3
    if grep "${expected_log_entry[index]}" $DUMP_FILE; then
      log "test for ${event_types[index]} succeded"
    else
      abort
    fi
    log "finished ${event_types[index]}"
  done
  log "finished test_event_types"
}

function last_endpoint_id {
  echo `cilium endpoint list|tail -n1|awk '{ print $1}'`
}

function container_addr {
  echo `docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' $CONTAINER`
}

function test_from {
  log "from filter"
  cilium config Debug=true DropNotification=true TraceNotification=true
  setup
  spin_up_container
  monitor_start --type debug --from $(last_endpoint_id)
  wait_for_log_entries 2
  # We are not expecting drop events so fail if they occur.
  if grep "DROP:" $DUMP_FILE; then
    abort
  fi
  wait_for_log_entries 1
  if grep "FROM $(last_endpoint_id) DEBUG: " $DUMP_FILE; then
    log "Test succeded test_from"
  else
    abort
  fi
}

function test_to {
  log "to filter"
  cilium config Debug=true DropNotification=true TraceNotification=true PolicyEnforcement=always
  setup
  spin_up_container
  monitor_start --type drop --to $(last_endpoint_id)
  # Packets should be dropped.
  set +e 
  ping6 -c 3 $(container_addr)
  set -e 
  if grep "FROM $(last_endpoint_id) DROP: " $DUMP_FILE; then
    log "Test succeded test_to"
  else
    abort
  fi
}

function test_related_to {
  log "related to filter"
  cilium config Debug=true DropNotification=true TraceNotification=true PolicyEnforcement=always
  setup
  spin_up_container
  monitor_start --type drop --related-to $(last_endpoint_id)
  set +e
  ping6 -c 3 $(container_addr)
  set -e
  monitor_stop
  monitor_resume --type debug --related-to $(last_endpoint_id)
  set +e
  ping6 -c 3 $(container_addr)
  set -e
  if grep "FROM $(last_endpoint_id) DEBUG: " $DUMP_FILE && \
   grep "FROM $(last_endpoint_id) DROP: " $DUMP_FILE; then
    log "Test succeded test_related_to"
  else
    abort
  fi
}

trap finish_test EXIT

test_event_types
test_from
test_to
test_related_to
cleanup

test_succeeded "${TEST_NAME}"
