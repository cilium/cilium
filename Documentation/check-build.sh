#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# This was ported from the makefile, it can probably be converted
# to Python (see e.g. https://stackoverflow.com/a/47657926), that
# way we might be able to call Sphinx only once and make it quicker

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_dir="${script_dir}/_build"
warnings="${build_dir}/warnings.txt"
spelling="${build_dir}/spelling/output.txt"

target="${1:-"html"}"
shift

cd "${script_dir}"
mkdir -p "${build_dir}"

build_with_spellchecker() {
    sphinx-build -b spelling -d "${build_dir}/doctrees" . "${build_dir}/spelling" -q -E 2> "${warnings}"
}

build_with_linkchecker() {
    sphinx-build -b linkcheck -d "${build_dir}/doctrees" . "${build_dir}/spelling" -q -E
}

filter_warnings() {
    grep -v \
        -e "tabs assets" \
        -e "misspelled words" \
        -e "RemovedInSphinx20Warning" \
        "${warnings}"
}

has_spelling_errors() {
    test "$(wc -l < "${spelling}")" -ne 0 
}

describe_spelling_errors() {
    printf "\nPlease fix the following spelling mistakes:\n"
    # show file paths relative to repo root
    sed 's/^/* Documentation\//' "${spelling}"
}

hint_about_wordlist_update() {
    new_words="$(sed -E 's/^([^:]+:){2} \((.*)\)/\2/g' "${spelling}" | sort -u | tr -d '\r\n' | sed "s/'/\\\\\\\\'/g")"
    printf "\nIf the words are not misspelled, run:\n%s %s\n" \
        "Documentation/update-spelling_wordlist.sh" "${new_words}"
}

if [ -n "${SKIP_LINT-}" ]; then
  echo "Skipping syntax and spelling validations..."
else
  echo "Validating documentation (syntax, spelling)..."
  if build_with_spellchecker ; then
    status_ok=0
    if filter_warnings > /dev/null ;  then
        printf "\nPlease fix the following documentation warnings:\n"
        filter_warnings
        status_ok=1
    fi

    if has_spelling_errors ; then
        describe_spelling_errors
        hint_about_wordlist_update
        status_ok=1
    fi

    if [ "${status_ok}" -ne 0 ] ; then
        exit 1
    fi
  fi
fi

# TODO: Fix broken links and re-enable this
# (https://github.com/cilium/cilium/issues/10601)
# echo "Checking links..."
# if ! build_with_linkchecker ; then
#     echo "Link check failed!"
#     exit 1
# fi

echo "Building documentation (${target})..."
exec sphinx-build -M "${target}" "${script_dir}" "${build_dir}" $@
