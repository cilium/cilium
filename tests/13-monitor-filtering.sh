#!/bin/bash

source "./helpers.bash"

logs_clear

echo "------ monitor filtering ------"

CLIENT_LABEL="client"
CONTAINER=monitor_tests

function cleanup {
  docker rm -f $CONTAINER 2> /dev/null || true
  docker network rm $TEST_NET > /dev/null 2>&1
  monitor_stop
}

function finish_test {
  gather_files 13-monitoring-filtering ${TEST_SUITE}
  cleanup
}

function spin_up_container {
  docker run -d --net cilium --name $CONTAINER -l $CLIENT_LABEL tgraf/netperf > /dev/null 2>&1
  docker exec -ti $CONTAINER ip -6 address list > /dev/null 2>&1
  docker exec -ti $CONTAINER ip -6 route list dev cilium0 > /dev/null 2>&1
}

function setup {
  cleanup
  create_cilium_docker_network
  logs_clear
  monitor_clear
}

function test_event_types {
  echo "------ event filter ------"
  cilium config Debug=true DropNotification=true TraceNotification=true

  event_types=( drop debug capture )
  expected_log_entry=( "Packet dropped" "DEBUG:" "DEBUG:" )

  for ((i=0;i<${#event_types[@]};++i)); do
    echo "------- ${event_types[i]} -------"
    setup
    monitor_start --type ${event_types[i]}
    spin_up_container
    wait_for_log_entries 3
    if grep "${expected_log_entry[i]}" $DUMP_FILE; then
      echo Test for ${event_types[i]} succeded
    else
      abort
    fi
  done
}

function last_endpoint_id {
  echo `cilium endpoint list|tail -n1|awk '{ print $1}'`
}

function container_addr {
  echo `docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' $CONTAINER`
}

function test_from {
  echo "------ from filter ------"
  cilium config Debug=true DropNotification=true TraceNotification=true
  setup
  spin_up_container
  monitor_start --type debug --from $(last_endpoint_id)
  wait_for_log_entries 2
  # We are not expecting drop events so fail if they occur.
  if grep "Packet dropped" $DUMP_FILE; then
    abort
  fi
  wait_for_log_entries 1
  if grep "FROM $(last_endpoint_id) DEBUG: " $DUMP_FILE; then
    echo Test succeded test_from
  else
    abort
  fi
}

function test_to {
  echo "------ to filter ------"
  cilium config Debug=true DropNotification=true TraceNotification=true PolicyEnforcement=always
  setup
  spin_up_container
  monitor_start --type drop --to $(last_endpoint_id)
  ping6 -c 3 $(container_addr)
  if grep "FROM $(last_endpoint_id) Packet dropped" $DUMP_FILE; then
    echo Test succeded test_to
  else
    abort
  fi
}

function test_related_to {
  echo "------ related to filter ------"
  cilium config Debug=true DropNotification=true TraceNotification=true PolicyEnforcement=always
  setup
  spin_up_container
  monitor_start --type drop --related-to $(last_endpoint_id)
  ping6 -c 3 $(container_addr)
  monitor_stop
  monitor_resume --type debug --related-to $(last_endpoint_id)
  ping6 -c 3 $(container_addr)
  if grep "FROM $(last_endpoint_id) DEBUG: " $DUMP_FILE && \
   grep "FROM $(last_endpoint_id) Packet dropped" $DUMP_FILE; then
    echo Test succeded test_from
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
