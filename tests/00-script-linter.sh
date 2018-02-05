#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Make sure each test has set the e and x flags.
function check_flags_set
{
  if grep -RL --include=\*.sh "set -.*e.*x" * | \
    grep -v "00-script-linter" | \
    grep -v "start.sh" | \
    grep -v "helpers.bash" | \
    grep -v "cilium-files" | \
    grep -v ".diff" | \
    grep -v ".yaml" | \
    grep -v "start_vms" | \
    grep -v ".json" ; then
    echo "Please make sure that all tests contain 'set -ex'"
    exit 1
  fi
}

check_flags_set
