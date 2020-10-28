#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cmdref_dir="${script_dir}/cmdref"

if ! git diff --quiet -- "${cmdref_dir}" ; then
    git --no-pager diff "${cmdref_dir}"
    echo "HINT: to fix this, run 'make -C Documentation update-cmdref'"
    exit 1
fi
