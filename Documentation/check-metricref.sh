set -o errexit
set -o nounset
set -o pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
observability_dir="$(cd "${script_dir}/observability" && pwd)"

if ! git diff --quiet -- "${observability_dir}" ; then
    git --no-pager diff "${observability_dir}"
    echo "HINT: to fix this, run 'make -C Documentation update-metricref'"
    exit 1
fi
