#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

log "Checking for deadlocks in cilium service log"
if $(journalctl -au cilium | grep -qi -B 5 -A 5 deadlock); then
	abort "Deadlock during test run detected, check the log above for context"
fi

test_succeeded "${TEST_NAME}"
