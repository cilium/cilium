#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

log "${TEST_NAME} has been deprecated and replaced by test/runtime/chaos.go: Checking for file-descriptor leak"
exit 0 

threshold=5000

fd_open=$(sudo lsof -p `pidof cilium-node-monitor` -p `pidof cilium-agent` -p `pidof cilium-docker` 2>/dev/null | wc -l)

if [[ ${fd_open} -gt ${threshold} ]]; then
    abort "Number of fd open seems abnormal: ${fd_open} (expecting less than ${threshold})"
fi

test_succeeded "${TEST_NAME}"
