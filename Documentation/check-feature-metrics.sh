#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
observability_dir="${script_dir}/observability"

# Ensure new files are also considered in the diff
git add --intent-to-add -- "${observability_dir}"

if ! git diff --quiet -- "${observability_dir}" ; then
    git --no-pager diff "${observability_dir}"
    echo "HINT: to fix this, run 'make -C Documentation update-feature-metrics'"
    exit 1
fi
