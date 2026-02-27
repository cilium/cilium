#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
metrics_dir="${script_dir}/observability"

if ! git diff --quiet -- "${metrics_dir}" ; then
    git --no-pager diff "${metrics_dir}"
    echo "HINT: to fix this, install via 'make kind-install-cilium-metrics' and run 'make -C Documentation update-metrics'"
    exit 1
fi
