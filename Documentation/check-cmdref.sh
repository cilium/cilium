#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cmdref_dir="${script_dir}/cmdref"

# Ensure new files are also considered in the diff
git add --intent-to-add -- "${cmdref_dir}"

if ! git diff --quiet -- "${cmdref_dir}" ; then
    git --no-pager diff "${cmdref_dir}"
    echo "HINT: to fix this, run 'make -C Documentation update-cmdref'"
    exit 1
fi
