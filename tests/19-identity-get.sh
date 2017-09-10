#!/bin/bash

# Tests to validate `cilium identity get` CLI commands.

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
  cilium policy delete --all 2> /dev/null || true
  docker rm -f foo foo bar baz 2> /dev/null || true
}

function finish_test {
  gather_files ${TEST_NAME} ${TEST_SUITE}
  cleanup
}

trap finish_test EXIT

cleanup
logs_clear

# Checks that the `cilium identity get <ID>` response matches expectations.
#
# The test launches three containers and waits until 3 endpoints are created in Cilium. It then extracts the security ID
# from the `cilium endpoint list` output.
function test_identity_get {
  remove_containers
  restart_cilium
  start_containers
  wait_for_endpoints 3
  cilium endpoint list
  local ID=$(cilium endpoint list | grep id.foo | awk '{print $3}')

  # Get expected response and replace all newline chars with a single space.
  local response=$(cilium identity get $ID | sed ':a;N;$!ba;s/\n/ /g')

  # Extract SHA256 value from response
  local str=$response
  local substring="labelsSHA256\": \""
  local len=${#substring}

  # Find the index of first occurrence of substring in response str
  local index=$(awk -v a="$str" -v b="$substring" 'BEGIN{print index(a,b)}')
  substring=${str:index + len - 1}
  local sha256="$( cut -d '"' -f 1 <<< "$substring" )"

  echo "Endpoint security ID is: $ID"
  local expected_response='{   "Payload": {     "id": '$ID',     "labels": [       "container:id.foo"     ],     "labelsSHA256": "'$sha256'"   } }'

  echo "Response is $response"

  if [[ "${expected_response}" != "${response}" ]]; then
    abort "Expected: ${expected_response}; Got: ${response}"
  fi
}

cilium endpoint list

create_cilium_docker_network

test_identity_get

test_succeeded "${TEST_NAME}"
