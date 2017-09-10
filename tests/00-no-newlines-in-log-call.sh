#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

if grep --include \*.go -r 'log\.' ../ | grep -v vendor \
  | grep -v contrib \
  | grep -v logging.go \
  | grep -F "\n"; then
  abort "found newline(s) in log call(s), please remove ending \n"
fi
