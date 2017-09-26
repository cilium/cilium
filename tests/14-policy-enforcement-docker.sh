#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

TEST_NET="cilium-net"
NUM_ENDPOINTS="3"

NAMESPACE="kube-system"
GOPATH="/home/vagrant/go"

ENABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled' -c"
DISABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Disabled' -c"

function cleanup {
  log "beginning cleanup for ${TEST_NAME}"
  log "removing containers foo bar and baz"
  docker rm -f foo bar baz 2> /dev/null || true
  policy_delete_and_wait "--all" 2> /dev/null || true
  log "removing docker network $TEST_NET"
  remove_cilium_docker_network
  cilium config PolicyEnforcement=default || true
  log "cleanup done for ${TEST_NAME}"
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}


#######################################
# Checks that the provided number of endpoints have policy enforcement enabled
# Globals:
#   ENABLED_CMD
# Arguments:
#   NUM_EPS: number of endpoints to check 
# Returns:
#   None
#######################################
function check_endpoints_policy_enabled {
  local NUM_EPS=$1
  log " checking if ${NUM_EPS} endpoints have policy enforcement enabled "
  cilium endpoint list
  POLICY_ENABLED_COUNT=`eval ${ENABLED_CMD}`
  if [ "${POLICY_ENABLED_COUNT}" -ne "${NUM_EPS}" ] ; then
    cilium config
    cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  log "${NUM_EPS} endpoints have policy enforcement enabled; continuing"
}

#######################################
# Checks that the provided number of endpoints have policy enforcement disabled
# Globals:
#   ENABLED_CMD
# Arguments:
#   NUM_EPS: number of endpoints to check 
# Returns:
#   None
#######################################
function check_endpoints_policy_disabled {
  local NUM_EPS=$1
  log "checking if ${NUM_EPS} endpoints have policy enforcement disabled"
  cilium endpoint list 
  POLICY_DISABLED_COUNT=`eval ${DISABLED_CMD}`
  if [ "${POLICY_DISABLED_COUNT}" -ne "${NUM_EPS}" ] ; then 
    cilium config
    cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  log "${NUM_EPS} endpoints have policy enforcement disabled; continuing"
}

function start_containers {
  docker run -dt --net=$TEST_NET --name foo -l id.foo -l id.teamA tgraf/netperf
  docker run -dt --net=$TEST_NET --name bar -l id.bar -l id.teamA tgraf/netperf
  docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf
}

function import_sample_policy {
  log "Importing L3 CIDR Policy"
  cat << EOF | policy_import_and_wait -
[{
     "endpointSelector": {"matchLabels":{"id.baz":""}},
     "egress": [{
         "toCIDR": [ "9.9.9.9/32" ]
     }]
 }]
EOF

}

trap finish_test EXIT
cleanup

# Restart cilium so we are sure it is running in 'default' mode.
service cilium restart 
wait_for_cilium_status

create_cilium_docker_network

start_containers
wait_for_endpoints ${NUM_ENDPOINTS} 

# Test 1: default mode, no K8s, Cilium launched.
# Default behavior is to have policy enforcement disabled for all endpoints
# if there are no rules added to Cilium, enabled for the endpoints if rules
# have been added that apply to running endpoints.
# Since no policies have been imported, all endpoints should have 
# policy enforcement disabled.
log "Test 1: default mode: test configuration with no policy imported"
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 2: default mode, no K8s, import policy.
# Import the following policy, which only applies to baz.
# Since policy enforcement is in 'default' mode for the daemon, policy enforcement 
# should be enabled for only one endpoint, baz.
log " Test 2: default mode: test with policy imported  "
import_sample_policy
check_endpoints_policy_enabled 1

# Test 3: default mode, delete policy.
# Since the policy repository is now empty, we expect that all endpoints should have policy enforcement disabled.
log " Test 3: default mode: check that policy enforcement for each endpoint is disabled after all policies are removed "
policy_delete_and_wait "--all"
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 4: default --> always mode, no policy imported.
# We expect that all endpoints should have policy enforcement enabled after this configuration is applied.
log " Test 4: default --> always mode: check that each endpoint has policy enforcement enabled with no policy imported "
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 5: always --> never mode, no policy imported.
# We expect that all endpoints should have policy enforcement disabled after this configuration is applied.
log " Test 5: always --> never mode: check that each endpoint has policy enforcement disabled with no policy imported "
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 6: never mode, import policy.
# Policy enforcement should be disabled for all endpoints.
log " Test 6: never  mode: check that each endpoint has policy enforcement disabled with policy imported "
import_sample_policy
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 7: never --> always mode, policy imported.
# Policy enforcement should be enabled for all endpoints.
log " Test 7: never --> always mode: check that each endpoint has policy enforcement enabled with policy imported "
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 8: always --> default mode, policy imported.
# Policy enforcement should be enabled for one endpoint, baz.
log " Test 8: always --> default mode: check that each endpoint has policy enforcement enabled with policy imported "
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled 1

# Test 9: default --> always mode, policy imported.
# Policy enforcement should be enabled for all endpoints.
log " Test 9: default --> always mode: check that each endpoint has policy enforcement enabled with a policy imported "
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 10: always mode, delete policy.
# Policy enforcement should be 'true' for all endpoints.
log " Test 10: always mode: check that each endpoint has policy enforcement enabled after policy is removed  "
policy_delete_and_wait "--all"
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 11: always mode, import policy.
# All endpoints should have policy enforcement enabled.
log " Test 11: always mode: check that each endpoint has policy enforcement enabled after policy is imported "
import_sample_policy
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 12: always --> never mode, policy imported.
# All endpoints should have policy enforcement disabled. 
log " Test 12: always --> never mode: check that each endpoint has policy disabled with a policy imported "
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 13: never mode, delete policy.
# All endpoints should have policy enforcement disabled.
log " Test 13: never mode: check that each endpoint has policy disabled when policy is deleted "
policy_delete_and_wait "--all"
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 14: never --> always, no policy imported.
# All endpoints should have policy enforcement enabled.
log " Test 14: never --> always mode: check that each endpoint has policy enforcement enabled with no policy imported "
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 15: always --> default, no policy imported.
# All endpoints should have policy enforcement disabled.
log " Test 15: always --> default mode: check that each endpoint has policy enforcement disabled with no policy imported "
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 16: default --> never, no policy imported.
# All endpoints should have policy enforcement disabled.
log " Test 16: default --> never mode: check that each endpoint has policy enforcement disabled with no policy imported "
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 17: never --> default, no policy imported.
# All endpoints should have policy enforcement disabled.
log " Test 17: never --> default mode: check that each endpoint has policy enforcement disabled with no policy imported  "
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

test_succeeded "${TEST_NAME}"
