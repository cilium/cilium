#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME="17-multiple-monitors"
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -uex

TEST_NET="cilium"
MON_1_OUTPUT=$(mktemp)
MON_2_OUTPUT=$(mktemp)
MON_3_OUTPUT=$(mktemp)

function cleanup {
  docker rm -f demo1 || true
  remove_cilium_docker_network
}

function lines_expected {
  expected=$1
  actual=`wc -l $2 | awk '{ print $1 }'`

  if [ $actual -lt $expected ]; then
    abort "monitor output lines($actual) in $2 is less than $expected"
  fi
}

trap cleanup EXIT

create_cilium_docker_network

cilium monitor > ${MON_1_OUTPUT} &
MON_1_PID=$!
cilium monitor > ${MON_2_OUTPUT} &
MON_2_PID=$!
cilium monitor > ${MON_3_OUTPUT} &
MON_3_PID=$!

if ! ps --pid $MON_1_PID  && ! ps --pid $MON_2_PID  && ! ps --pid $MON_3_PID; then
  abort "expected three monitors to be running"
fi

docker run -d --net cilium --name demo1 -l client tgraf/netperf
docker exec -i demo1 ip -6 address list
docker exec -i demo1 ip -6 route list dev cilium0
cilium endpoint list
docker rm -f demo1

lines_expected 3 ${MON_1_OUTPUT}
lines_expected 3 ${MON_2_OUTPUT}
lines_expected 3 ${MON_3_OUTPUT}

kill ${MON_1_PID} ${MON_2_PID} ${MON_3_PID}

if ! diff3 ${MON_1_OUTPUT} ${MON_2_OUTPUT} ${MON_3_OUTPUT}; then
  abort "Monitor output does not match `diff ${MON_1_OUTPUT} ${MON_2_OUTPUT}`"
fi

test_succeeded "${TEST_NAME}"
