#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -e

logs_clear

log "checking help output of \"cilium help\" (should NOT be on stdout)"
stdout_msg=$($dir/../daemon/cilium help bpf 2>/dev/null)
if [[ -n "$stdout_msg" ]]; then
    abort "cilium help should NOT print to stdout"
fi

log "checking help output of \"cilium help\" (should be on stderr)"
stderr_combined=$($dir/../daemon/cilium help bpf 2>&1 /dev/null)
if [[ -z  $stderr_combined  ]]; then
    abort "cilium help should print to stderr"
fi

test_succeeded "${TEST_NAME}"
