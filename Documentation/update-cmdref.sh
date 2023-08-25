#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "${script_dir}/.." && pwd)"
cmdref_dir="${script_dir}/cmdref"

generators=(
    "cilium/cilium cmdref -d"
    "daemon/cilium-agent cmdref"
    "bugtool/cilium-bugtool cmdref -d"
    "cilium-health/cilium-health --cmdref"
    "operator/cilium-operator --cmdref"
    "operator/cilium-operator-aws --cmdref"
    "operator/cilium-operator-azure --cmdref"
    "operator/cilium-operator-generic --cmdref"
    "operator/cilium-operator-alibabacloud --cmdref"
)

for g in "${generators[@]}" ; do
    ${source_dir}/${g} "${cmdref_dir}"
done
