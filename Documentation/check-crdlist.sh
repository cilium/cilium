#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_file="${script_dir}/crdlist.rst"

if ! git diff --quiet -- "$target_file" ; then
    git --no-pager diff -- "$target_file"
    echo "HINT: to fix this, run 'make -C Documentation update-crdlist'"
    exit 1
fi
