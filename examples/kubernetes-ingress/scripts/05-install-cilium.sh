#!/usr/bin/env bash
#
# It checks if a policy is loaded in cilium. It will use default values from
# ./helpers.bash
#######################################

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${dir}/helpers.bash"

log "Checking cilium policies..."

set -e

cilium policy get

log "Checking cilium policies... DONE!"
