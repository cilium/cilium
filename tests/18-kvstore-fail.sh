#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

# If you want to run this alone, remember to setup PATH for clang and friends.
export PATH=$PATH:/usr/local/go/bin:/usr/local/clang/bin:/home/vagrant/go/bin:/home/vagrant/bin

function cleanup {
  killall cilium-agent || true
  systemctl stop cilium-etcd || true
  systemctl stop cilium-consul || true
  systemctl restart cilium
}

function finish_test {
  gather_files ${TEST_NAME}  ${TEST_SUITE}
  cleanup
}

function test_kvstore {
  PORT=$2
  KV=$1 
  KV_OPTS="--kvstore $KV --kvstore-opt $KV.address=127.0.0.1:$PORT"
  CILIUM_AGENT=../daemon/cilium-agent
  AGENT_PID=""

  # Give the daemon a chance to start
  $CILIUM_AGENT $KV_OPTS &
  AGENT_PID=$!
  wait_for_agent_socket 60

  echo "--- Check that the daemon started up succesfully ---"
  if [ ! -S $AGENT_SOCK_PATH ]; then
    abort "No socket at $AGENT_SOCK_PATH"
  fi

  if ! ps -p $AGENT_PID; then
    abort "The daemon should be running"
  fi

  if ! cilium status | grep "KVStore:            Ok"; then
    abort "KVStore should be Ok"
  fi

  kill $AGENT_PID

  systemctl stop cilium-$KV

  echo "--- Wait for daemon to exhaust maxTries ---"
  $CILIUM_AGENT $KV_OPTS &
  AGENT_PID=$!
  wait_for_kill $AGENT_PID 240

  if [ -S $AGENT_SOCK_PATH ]; then
    abort "Found $AGENT_SOCK_PATH. The daemon should not be running."
  fi
}

# FIXME: Re-enable when test is stable
#trap finish_test EXIT
#
#systemctl stop cilium
#
#test_kvstore consul "8500"
#
#systemctl start cilium-etcd
#
#test_kvstore etcd "4001"

test_succeeded "${TEST_NAME}"
