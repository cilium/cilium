#!/bin/bash

# Tests to validate `cilium identity get` CLI commands.

source "./helpers.bash"

TEST_NET="cilium-net"

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
    gather_files 15-policy-config ${TEST_SUITE}
    cilium policy delete --all 2> /dev/null || true
    docker rm -f foo foo bar baz 2> /dev/null || true
}

trap cleanup EXIT

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
    ID=$(cilium endpoint list | grep id.foo | awk '{print $3}')

    # Get expected response and replace all newline chars with a single space.
    response=$(cilium identity get $ID | sed ':a;N;$!ba;s/\n/ /g')

    # Extract SHA256 value from response
    str=$response
    substring="labelsSHA256\": \""
    len=${#substring}

    # Find the index of first occurrence of substring in response str
    index=$(awk -v a="$str" -v b="$substring" 'BEGIN{print index(a,b)}')
    substring=${str:index + len - 1}
    sha256="$( cut -d '"' -f 1 <<< "$substring" )"

    echo "Endpoint security ID is: $ID"
    expected_response='{   "Payload": {     "id": '$ID',     "labels": [       "container:id.foo"     ],     "labelsSHA256": "'$sha256'"   } }'

    echo "Response is $response"

    if [[ "${expected_response}" != "${response}" ]]; then
        abort "Expected: ${expected_response}; Got: ${response}"
    fi
}

cilium endpoint list
cilium identity get --list

docker network inspect $TEST_NET 2> /dev/null || {
        docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

test_identity_get
