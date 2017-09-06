#!/bin/bash

# Tests to validate `cilium identity list` CLI commands.

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

function start_containers {
  docker run -dt --net=$TEST_NET --name foo -l id.foo tgraf/netperf
  docker run -dt --net=$TEST_NET --name bar -l id.bar tgraf/netperf
  docker run -dt --net=$TEST_NET --name baz -l id.baz tgraf/netperf
}

function remove_containers {
  docker rm -f foo foo bar baz 2> /dev/null || true
}

function restart_cilium {
  echo "------ restarting cilium ------"
  service cilium restart
  echo "------ waiting for cilium agent get up and running ------"
  wait_for_cilium_status
}

function cleanup {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cilium policy delete --all 2> /dev/null || true
  docker rm -f foo foo bar baz 2> /dev/null || true
}

trap cleanup EXIT

cleanup
logs_clear

# Checks that the `cilium identity list "<labels>"` response matches expectations.
#
# The test launches three containers and waits until 3 endpoints are created in Cilium. It then extracts the security ID
# from the `cilium endpoint list` output.
function test_identity_list {
  remove_containers
  restart_cilium
  start_containers
  wait_for_endpoints 3
  cilium endpoint list
  local ID=$(cilium endpoint list | grep id.foo | awk '{print $3}')

  # Get expected response and replace all newline chars with a single space.
  local response=$(cilium identity list "container:id.foo" | sed ':a;N;$!ba;s/\n/ /g')

  echo "Endpoint security ID is: $ID"

  local expected_response='Identities in use by endpoints: (Note: If labels have been provided as parameters, only matching identities will be displayed) [   {     "id": '$ID',     "labels": [       "container:id.foo"     ]   } ]'

  echo "Response is $response"

  if [[ "${expected_response}" != "${response}" ]]; then
    abort "Expected: ${expected_response}; Got: ${response}"
  fi
}

# Checks that the `cilium identity list --reserved` response matches expectations.
function test_identity_list_reserved {
  local response=$(cilium identity list --reserved | sed ':a;N;$!ba;s/\n/ /g' | grep '1 host.*2 world\|2 world.*1 host')
  local exit_code=$?

  echo "Response is $response"

  if [[ 0 != ${exit_code} ]]; then
    abort "Expected: 0 exit code; Got: ${exit_code}"
  fi
}

cilium identity list
cilium identity list "container:id.foo"

create_cilium_docker_network

test_identity_list

cleanup
logs_clear

test_identity_list_reserved

test_succeeded "${TEST_NAME}"
