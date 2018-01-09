#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/../cluster/env.bash"

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

log "Checking for deadlocks in k8s cilium log"
if $(docker ps -a | grep cilium-agent | awk '{print $1}' | xargs -n1 docker logs 2>&1 | grep -qi -B 5 -A 5 deadlock); then
	abort "Deadlock during test run detected, check Cilium logs for context"
fi

test_succeeded "${TEST_NAME}"
