#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cmdref_dir="${source_dir}/cmdref"

generators=(
    "../cilium/cilium cmdref -d"
    "../daemon/cilium-agent --cmdref"
    "../bugtool/cilium-bugtool cmdref -d"
    "../cilium-health/cilium-health --cmdref"
    "../operator/cilium-operator --cmdref"
)

for g in "${generators[@]}" ; do
    ${source_dir}/${g} "${cmdref_dir}"
done
