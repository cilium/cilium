#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex

log "${TEST_NAME} has been deprecated and replaced by test/runtime/Policies.go: Validates Example Policies"

exit 0

code=0

function check_coverage() {
  policy=$1
  if [ ! -f $policy.json ]; then
    log "Missing $policy.json"
    code=1
  fi
  if [ ! -f $policy.yaml ]; then
    log "Missing $policy.yaml"
    code=1
  fi
}

set +x

log "Validating demos"
for p in $dir/../examples/demo/*.json ; do
  if ! cilium policy validate $p; then
    log "$p is not valid"
    code=1
  fi
done

log "Validate JSON examples"
for p in `find $dir/../examples/policies/ -name '*.json'`; do
  if ! cilium policy validate $p; then
    log "$p is not valid"
    code=1
  fi
  check_coverage "${p%.*}"
done

log "Validate YAML examples"
for p in `find $dir/../examples/policies/ -name '*.yaml'`; do
  if ! yamllint -c $dir/yaml.config $p; then
    log "$p is not valid"
    code=1
  fi
done

exit $code
