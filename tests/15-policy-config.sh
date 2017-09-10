#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

LIST_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled\|Disabled'"
CFG_CMD="cilium config | grep PolicyEnforcement | awk '{print \$2}'"
ALLOWED="Verdict: allowed"

function start_containers {
  log "starting containers"
  docker run -dt --net=$TEST_NET --name foo -l id.foo -l id.teamA tgraf/netperf
  docker run -dt --net=$TEST_NET --name bar -l id.bar -l id.teamA tgraf/netperf
  docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf
  log "containers started and ready"
}

function remove_containers {
  log "removing containers"
  docker rm -f foo bar baz 2> /dev/null || true
  log "done removing containers"
}

function restart_cilium {
  log "restarting cilium "
  service cilium restart
  log "waiting for cilium agent get up and running"
  wait_for_cilium_status
}

function import_test_policy {
  log "importing test policy"
  cat <<EOF | cilium -D policy import -
  [{
    "endpointSelector": {"matchLabels":{"id.bar":""}},
    "ingress": [{
      "fromEndpoints": [
      {"matchLabels":{"reserved:host":""}},
      {"matchLabels":{"id.foo":""}}
    ]
          }]
  }]
EOF
}

function cleanup {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  policy_import_and_wait "--all" 2> /dev/null || true
  remove_containers
}

function check_endpoints_policy_enabled {
  log "checking if all endpoints have policy enforcement enabled "
  POLICY_ENFORCED=`eval ${LIST_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "Enabled" ]]; then
      cilium config
      cilium endpoint list
      abort "Policy Enabled should be set to 'Enabled' since there are policies added to Cilium"
    fi
  done
}

function check_endpoints_policy_disabled {
  log "checking if all endpoints have policy enforcement disabled "
  POLICY_ENFORCED=`eval ${LIST_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "Disabled" ]]; then
      cilium config
      cilium endpoint list
      abort "Policy Enforcement should be set to 'Disabled' for all endpoints"
    fi
  done
}

function check_config_policy_enabled {
  log "checking if cilium daemon has policy enforcement enabled "
  cilium config
        POLICY_ENFORCED=`eval ${CFG_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "always" ]]; then
                        cilium config
            cilium endpoint list  
      abort "Policy Enforcement should be set to 'always' for the daemon"
    fi
  done
}

function check_config_policy_disabled {
  log "checking if cilium daemon has policy enforcement disabled "
  cilium config
  POLICY_ENFORCED=`eval ${CFG_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "never" ]]; then
      cilium config
      cilium endpoint list
      abort "Policy Enforcement should be set to 'never' for the daemon"
    fi
  done
}

function check_config_policy_default {
  log "checking if cilium daemon has policy enforcement set to default "
  cilium config
  POLICY_ENFORCED=`eval ${CFG_CMD}`
  for line in $POLICY_ENFORCED; do
    if [[ "$line" != "default" ]]; then
      cilium config
      cilium endpoint list
      abort "Policy Enforcement should be set to 'default' for the daemon"
    fi
  done
}

function test_default_policy_configuration {
  log "test default configuration for enable-policy "
  # cilium-agent has enable-policy flag, which by default is set as "default".
  # Expected behavior is that if Kubernetes is not enabled, policy enforcement is enabled if at least one policy exists.
  # If no policy exists, then policy enforcement is disabled.
  remove_containers
  restart_cilium
  start_containers

  wait_for_endpoints 3
  check_config_policy_default
  check_endpoints_policy_disabled
  # TODO - renable when we clear conntrack state upon policy deletion.
  #ping_success foo bar
  #ping_success foo baz

  import_test_policy
  wait_for_endpoints 3
  check_endpoints_policy_enabled
  ping_success foo bar
  ping_fail foo baz || true

  cilium policy delete --all
  wait_for_endpoints 3
  ping_success foo baz
  ping_success foo bar
}

function test_default_to_true_policy_configuration {
  log "test that policy enforcement flag gets updated with no running endpoints: true "
  remove_containers
  # Make sure cilium agent starts in 'default' mode, so restart it.
  restart_cilium
  import_test_policy
  check_config_policy_default
  log "setting cilium agent PolicyEnforcement=always"
  cilium config PolicyEnforcement=always
  check_config_policy_enabled
  log "deleting policy "
  cilium policy delete --all
  # After policy is deleted, policy enforcement should still be enabled.
  check_config_policy_enabled
}

function test_default_to_false_policy_configuration {
  log "test that policy enforcement flag gets updated with no running endpoints: false "
  remove_containers
  # Make sure cilium agent starts in 'default' mode, so restart it.
  restart_cilium
  import_test_policy
  check_config_policy_default
  log "setting cilium agent Policy=never"
  cilium config PolicyEnforcement=never
  check_config_policy_disabled
  log "deleting policy "
  cilium policy delete --all
  # After policy is deleted, policy enforcement should be disabled.
  check_config_policy_disabled
}

function test_true_policy_configuration {
  log "test true configuration for enable-policy "
  remove_containers
  restart_cilium
  cilium config PolicyEnforcement=always
  start_containers

  wait_for_endpoints 3
  check_config_policy_enabled
  check_endpoints_policy_enabled
  ping_fail foo bar || true
  import_test_policy
  
  wait_for_endpoints 3
  check_config_policy_enabled
  check_endpoints_policy_enabled
  ping_success foo bar
  cilium policy delete --all
  
  wait_for_endpoints 3
  check_config_policy_enabled
  # TODO - renable when we clear conntrack state upon policy deletion. 
  # ping_fail foo bar || true
}

function test_false_policy_configuration {
  log "test false configuration for enable-policy "
  remove_containers
  restart_cilium
  cilium config PolicyEnforcement=never
  start_containers

  wait_for_endpoints 3
  check_config_policy_disabled
  check_endpoints_policy_disabled
  ping_success foo bar
  import_test_policy
  wait_for_endpoints 3
  check_config_policy_disabled
  check_endpoints_policy_disabled
  ping_success foo bar
  cilium policy delete --all
  wait_for_endpoints 3
  check_config_policy_disabled
}

function ping_fail {
  C1=$1
  C2=$2
  log "pinging $C2 from $C1 (expecting failure) "
  docker exec -i  ${C1} bash -c "ping -c 5 ${C2}" && {
      abort "Error: Unexpected success pinging ${C2} from ${C1}"
  }
}

function ping_success {
  C1=$1
  C2=$2
  log "pinging $C2 from $C1 (expecting success) "
  docker exec -i ${C1} bash -c "ping -c 5 ${C2}" || {
    abort "Error: Could not ping ${C2} from ${C1}"
  }
}

function test_policy_trace_policy_disabled {
  # If policy enforcement is disabled, then `cilium policy trace` should return that traffic is allowed between all security identities.
  remove_containers
  restart_cilium
  start_containers
  
  wait_for_endpoints 3
  FOO_ID=$(cilium endpoint list | grep id.foo | awk '{print $1}')
  BAR_ID=$(cilium endpoint list | grep id.bar | awk '{ print $1}')  
  log "verify verbose trace for expected output using endpoint IDs "
  TRACE_OUTPUT=$(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v)
  log "Trace output: ${TRACE_OUTPUT}"
  DIFF=$(diff -Nru <(echo "$ALLOWED") <(cilium policy trace --src-endpoint $FOO_ID --dst-endpoint $BAR_ID -v | grep "Verdict:")) || true
  if [[ "$DIFF" != "" ]]; then
    abort "DIFF: $DIFF"
  fi
}



trap cleanup EXIT

cleanup
logs_clear

create_cilium_docker_network

test_policy_trace_policy_disabled
test_default_policy_configuration
test_default_to_true_policy_configuration
test_default_to_false_policy_configuration
test_true_policy_configuration
test_false_policy_configuration

test_succeeded "${TEST_NAME}"
