#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helm_values="${script_dir}/helm-values.rst"

if ! git diff --quiet -- "${helm_values}" ; then
    git --no-pager diff "${helm_values}"
    echo "HINT: to fix this, run 'make -C Documentation update-helm-values'"
    exit 1
fi
