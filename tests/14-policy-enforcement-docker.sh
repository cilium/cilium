#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set -ex

TEST_NET="cilium-net"
DEMO_CONTAINER="cilium/demo-client"
HTTPD_CONTAINER_NAME="service1-instance1"
ID_SERVICE1="id.service1"
ID_SERVICE2="id.service2"
NUM_ENDPOINTS="3"

NAMESPACE="kube-system"
GOPATH="/home/vagrant/go"
DENIED="Result: DENIED"
ALLOWED="Result: ALLOWED"
TEST_NAME="14-policy-enforcement-docker"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"

MINIKUBE="${dir}/../../../examples/minikube"
K8SDIR="${dir}/../../../examples/kubernetes"

ENABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Enabled' -c"
DISABLED_CMD="cilium endpoint list | awk '{print \$2}' | grep 'Disabled' -c"
CFG_CMD="cilium config | grep Policy | grep -v PolicyTracing | awk '{print \$2}'"

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

function ping_fail {
  C1=$1
  C2=$2
  echo "------ pinging $C2 from $C1 (expecting failure) ------"
  docker exec -i  ${C1} bash -c "ping -c 5 ${C2}" && {
    abort "Error: Unexpected success pinging ${C2} from ${C1}"
  }
}

function ping_success {
  C1=$1
  C2=$2
  echo "------ pinging $C2 from $C1 (expecting success) ------"
  docker exec -i ${C1} bash -c "ping -c 5 ${C2}" || {
    abort "Error: Could not ping ${C2} from ${C1}"
  }
}


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

function check_config_policy_enabled {
        echo "---- checking if cilium daemon has policy enforcement enabled ----"
        POLICY_ENFORCED=`eval ${CFG_CMD}`
        for line in $POLICY_ENFORCED; do
                if [[ "$line" != "Enabled" ]]; then
                        cilium config
                        cilium endpoint list
                        abort "Policy Enforcement should be set to 'Enabled' for the daemon"
                fi
        done
}

function check_config_policy_disabled {
        echo "---- checking if cilium daemon has policy enforcement disabled ----"
        POLICY_ENFORCED=`eval ${CFG_CMD}`
        for line in $POLICY_ENFORCED; do
                if [[ "$line" != "Disabled" ]]; then
                        cilium config
                        cilium endpoint list
                        abort "Policy Enforcement should be set to 'Disabled' for the daemon"
                fi
        done
}

function start_containers {
        docker run -dt --net=$TEST_NET --name foo -l id.foo -l id.teamA tgraf/netperf
        docker run -dt --net=$TEST_NET --name bar -l id.bar -l id.teamA tgraf/netperf
        docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf
}

trap finish_test EXIT

cleanup

service cilium restart 
wait_for_cilium_status

echo "------ creating Docker network of type Cilium ------"
docker network create --ipv6 --subnet ::1/112 --driver cilium --ipam-driver cilium ${TEST_NET}

start_containers
wait_for_endpoints ${NUM_ENDPOINTS} 

# Test 1: Test default behavior of Cilium when launched using Docker.
# Default behavior is to have policy enforcement disabled for all endpoints that have
# no rules applying to them. Since no policies have been imported, all endpoints should have 
# policy enforcement disabled.
echo "---- Test 1: default mode: test configuration with no policy imported ----"


echo "---- Policy in ${CILIUM_POD_1} (should be empty) ----"
cilium policy get

check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 2: Import policy with 'default' policy enforcement mode.
# Import the following policy, which only applies to app3. 
# Since policy enforcement is in 'default' mode for the daemon / not running alongside K8s, policy enforcement 
# should be enabled for all endpoints.
echo "---- Test 2: default mode: test with policy imported  ----"

echo "---- Importing L3 CIDR Policy ----"
cat << EOF | policy_import_and_wait -
[{
     "endpointSelector": {"matchLabels":{"k8s:id":"app3"}},
     "egress": [{
         "toCIDR": [ { "ip": "9.9.9.9/32" } ]
     }]
 }]
EOF

echo "---- Policies in cilium ----"
cilium policy get

check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 3: Delete policy and check that all endpoints have policy enforcement disabled.
# Delete the aforementioned policy. Since the policy repository is now empty, we expect
# that all endpoints should have policy enforcement disabled.
echo "---- Test 3: default mode: check that policy enforcement for each endpoint is disabled after all policies are removed ----"
policy_delete_and_wait "--all"
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 4: Change daemon's policy enforcement configuration from 'default' to 'true' with no policy imported. 
#We expect that all endpoints should have policy enforcement enabled after this configuration is applied.
echo "---- Test 4: enabled mode: check that each endpoint has policy enforcement enabled with no policy imported ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 5: Change daemon's policy enforcement configuration from 'true' to 'false'.
# We expect that all endpoints should have policy enforcement disabled after this configuration is applied.
echo "---- Test 5: disabled mode: check that each endpoint has policy enforcement disabled with no policy imported ----"
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 6: Import a policy while policy enforcement is disabled.
# Policy enforcement should be disabled for all endpoints.
echo "---- Test 6: disabled mode: check that each endpoint has policy enforcement disabled with policy imported ----"
echo "---- Importing L3 CIDR Policy ----"
cat << EOF | policy_import_and_wait -
[{
     "endpointSelector": {"matchLabels":{"k8s:id":"app3"}},
     "egress": [{
         "toCIDR": [ { "ip": "9.9.9.9/32" } ]
     }]
 }]
EOF

echo "---- Policies in cilium ----"
cilium policy get

check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 7: Change daemon's policy enforcement configuration from 'false' to 'true' with a policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 7 ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 8: Change daemon's policy enforcement configuration from 'true' to 'default' with a policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 8 ----"
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 9: Change daemon's policy enforcement configuration from 'default' to 'true' with a policy imported.
# Policy enforcement should be enabled for all endpoints.
echo "---- Test 9 ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 10: Delete policy while policy enforcement is set to 'true'. 
# Policy enforcement should be 'true' for all endpoints.
echo "---- Test 10 ----"
policy_delete_and_wait "--all"
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 11: Import a policy while policy enforcement is set to 'true'. 
# All endpoints should have policy enforcement enabled.
echo "---- Test 11 ----"
echo "---- Importing L3 CIDR Policy ----"
cat << EOF | policy_import_and_wait -
[{
     "endpointSelector": {"matchLabels":{"k8s:id":"app3"}},
     "egress": [{
         "toCIDR": [ { "ip": "9.9.9.9/32" } ]
     }]
 }]
EOF
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 12: Set policy enforcement 'true' --> 'false' while a policy is imported.
# All endpoints should have policy enforcement disabled. 
echo "---- Test 12 ----"
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 13: Delete a policy while policy enforcement is set to 'false.
# All endpoints should have policy enforcement disabled.
echo "---- Test 13 ----"
policy_delete_and_wait "--all"
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 14: Set policy enforcement 'false' --> 'true' with no policy imported.
# All endpoints should have policy enforcement enabled.
echo "---- Test 14 ----"
cilium config PolicyEnforcement=always
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_enabled ${NUM_ENDPOINTS}

# Test 15: Set policy enforcement 'true' --> 'default' with no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 15 ----"
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 16: Set policy enforcement 'default' --> 'false' with no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 16 ----"
cilium config PolicyEnforcement=never
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}

# Test 17: Set policy enforcement 'false' --> 'default' with no policy imported.
# All endpoints should have policy enforcement disabled.
echo "---- Test 17 ----"
cilium config PolicyEnforcement=default
wait_for_endpoints ${NUM_ENDPOINTS}
check_endpoints_policy_disabled ${NUM_ENDPOINTS}
