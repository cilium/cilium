#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

echo "WARNING: There is a bug in docutils which may result in failure of this script. For ref: https://github.com/cilium/cilium/pull/27116#issuecomment-1752760611"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_dir="${script_dir}/_build"
warnings="${build_dir}/links_warnings.txt"
filtered_warnings="${build_dir}/filtered_links_warnings.txt"
linksdir="${build_dir}/links"

cd "${script_dir}"
mkdir -p "${build_dir}"
rm -f -- "${warnings}"
rm -f -- "${filtered_warnings}"

filter_warnings() {
    [ -s "${warnings}" ] || return
    grep -v -E \
        -e "/_api/v1/.*/README\.md:[0-9]+: WARNING: 'myst' reference target not found:" \
        -e "/.*:[0-9]+: WARNING: circular inclusion in \"include\" directive" \
        "${warnings}"
}

has_build_warnings() {
    filter_warnings > /dev/null
}

build_with_linkchecker() {
    rm -rf "${linksdir}"

    sphinx-build -b linkcheck -d "${build_dir}/doctrees" . "${linksdir}" \
        --color -E -w "${warnings}" -W --keep-going 2>/dev/null
}

echo "Checking links..."
if ! build_with_linkchecker ; then
    if has_build_warnings; then
        printf "\nPlease fix the following documentation warnings:\n"
        filter_warnings
        printf "\nAdding the warnings to the file.\n"
        filter_warnings | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' > "${filtered_warnings}"
        exit 1
    fi
fi
echo "Done checking links."
