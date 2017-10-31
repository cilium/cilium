#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

function check_no_sleep {
  if grep -R "sleep" * | \
     grep -v "00-script-linter" | \
     grep -v "helpers.bash" | \
     grep -v "cilium-files" | \
     grep -v ".diff" | \
     grep -v ".yaml" | \
     grep -v ".json"; then
    
    echo "Please do not use sleep, consider using one of the wait helper functions."
    echo "If none of the provided wait functions fit your use case please discuss your use case on Slack and / or file a bug."
    exit 1
  fi
}

# Make sure each test has set the e and x flags.
function check_flags_set
{
  if grep -RL --include=\*.sh "set -.*e.*x" * | \
    grep -v "00-script-linter" | \
    grep -v "00-fmt" | \
    grep -v "start.sh" | \
    grep -v "helpers.bash" | \
    grep -v "cilium-files" | \
    grep -v ".diff" | \
    grep -v ".yaml" | \
    grep -v ".json" ; then
    echo "Please make sure that all tests contain 'set -ex'"
    exit 1
  fi
}

check_no_sleep
check_flags_set
