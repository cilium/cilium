#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set -ex

TEST_NET="cilium-net"
NUM_ENDPOINTS="3"

NAMESPACE="kube-system"
GOPATH="/home/vagrant/go"
TEST_NAME="14-policy-enforcement-docker"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"

ENABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled' -c"
DISABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Disabled' -c"

function cleanup {
  docker rm -f foo foo bar baz 2> /dev/null || true
  policy_delete_and_wait "--all" 2> /dev/null || true
  docker network rm ${TEST_NET} 2> /dev/null || true
  cilium config PolicyEnforcement=default || true
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
  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement enabled ----"
  cilium endpoint list
  POLICY_ENABLED_COUNT=`eval ${ENABLED_CMD}`
  if [ "${POLICY_ENABLED_COUNT}" -ne "${NUM_EPS}" ] ; then
    cilium config
    cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo "---- ${NUM_EPS} endpoints have policy enforcement enabled; continuing ----"
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
  echo "---- checking if ${NUM_EPS} endpoints have policy enforcement disabled ----"
  cilium endpoint list 
  POLICY_DISABLED_COUNT=`eval ${DISABLED_CMD}`
  if [ "${POLICY_DISABLED_COUNT}" -ne "${NUM_EPS}" ] ; then 
    cilium config
    cilium endpoint list
    abort "Policy Enforcement  should be set to 'Disabled' since policy enforcement was set to never be enabled"
  fi
  echo  "---- ${NUM_EPS} endpoints have policy enforcement disabled; continuing ----"
}

function start_containers {
  docker run -dt --net=$TEST_NET --name foo -l id.foo -l id.teamA tgraf/netperf
  docker run -dt --net=$TEST_NET --name bar -l id.bar -l id.teamA tgraf/netperf
  docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf
}

function import_sample_policy {
  echo "---- Importing L3 CIDR Policy ----"
  cat << EOF | policy_import_and_wait -
[{
     "endpointSelector": {"matchLabels":{"k8s:id":"app3"}},
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
# if there are no rules  added to Cilium, enabled for all endpoints if rules
# have been added, regardless of if they apply to the endpoint or not.
# Since no policies have been imported, all endpoints should have 
# policy enforcement disabled.
echo "---- Test 1: default mode: test configuration with no policy imported ----"
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 2: default mode, no K8s, import policy.
# Import the following policy, which only applies to app3. 
# Since policy enforcement is in 'default' mode for the daemon / not running alongside K8s, policy enforcement 
# should be enabled for all endpoints.
echo "---- Test 2: default mode: test with policy imported  ----"
import_sample_policy
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 3: default mode, no K8s, delete policy.
# Since the policy repository is now empty, we expect that all endpoints should have policy enforcement disabled.
echo "---- Test 3: default mode: check that policy enforcement for each endpoint is disabled after all policies are removed ----"
policy_delete_and_wait "--all"
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 4: default --> always mode, no K8s, no policy imported.
# We expect that all endpoints should have policy enforcement enabled after this configuration is applied.
echo "---- Test 4: default --> always mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 5: always --> never mode, no K8s, no policy imported.
# We expect that all endpoints should have policy enforcement disabled after this configuration is applied.
echo "---- Test 5: always --> never mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 6: never mode, no K8s, import policy.
# Policy enforcement should be disabled for all endpoints.
echo "---- Test 6: never  mode: check that each endpoint has policy enforcement disabled with policy imported ----"
import_sample_policy
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 7: never --> always mode, no K8s, policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 7: never --> always mode: check that each endpoint has policy enforcement enabled with policy imported ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 8: always --> default mode, no K8s, policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 8: always --> default mode: check that each endpoint has policy enforcement enabled with policy imported ----"
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 9: default --> always mode, no K8s, policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 9: default --> always mode: check that each endpoint has policy enforcement enabled with a policy imported ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 10: always mode, no K8s, delete policy.
# Policy enforcement should be 'true' for all endpoints.
echo "---- Test 10: always mode: check that each endpoint has policy enforcement enabled after policy is removed  ----"
policy_delete_and_wait "--all"
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 11: always mode, no K8s, import policy.
# All endpoints should have policy enforcement enabled.
echo "---- Test 11: always mode: check that each endpoint has policy enforcement enabled after policy is imported ----"
import_sample_policy
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 12: always --> never mode, no K8s, policy imported.
# All endpoints should have policy enforcement disabled. 
echo "---- Test 12: always --> never mode: check that each endpoint has policy disabled with a policy imported ----"
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 13: never mode, no K8s, delete policy.
# All endpoints should have policy enforcement disabled.
echo "---- Test 13: never mode: check that each endpoint has policy disabled when policy is deleted ----"
policy_delete_and_wait "--all"
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 14: never --> always, no K8s, no policy imported.
# All endpoints should have policy enforcement enabled.
echo "---- Test 14: never --> always mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 15: always --> default, no K8s, no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 15: always --> default mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 16: default --> never, no K8s, no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 16: default --> never mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 17: never --> default, no K8s, no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 17: never --> default mode: check that each endpoint has policy enforcement disabled with no policy imported  ----"
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}
