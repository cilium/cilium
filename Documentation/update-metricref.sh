#!/usr/bin/env bash
#
set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "${script_dir}/.." && pwd)"

go run ${source_dir}/tools/metricdoctool/metricdoctool.go > ${script_dir}/observability/metrics.rst
