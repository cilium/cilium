#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
config_dir="${script_dir}/configuration"

if ! git diff --quiet -- "${config_dir}" ; then
    git --no-pager diff "${config_dir}"
    echo "HINT: to fix this, run 'make -C Documentation api-flaggen'"
    exit 1
fi

