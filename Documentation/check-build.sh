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
spelldir="${build_dir}/spelling"

target="${1:-"html"}"
shift

cd "${script_dir}"
mkdir -p "${build_dir}"

build_with_spellchecker() {
    rm -rf "${spelldir}"
    sphinx-build -b spelling -d "${build_dir}/doctrees" . "${spelldir}" -q -E 2> "${warnings}"
}

build_with_linkchecker() {
    sphinx-build -b linkcheck -d "${build_dir}/doctrees" . "${spelldir}" -q -E
}

has_spelling_errors() {
    test -n "$(ls "${spelldir}")"
}

describe_spelling_errors() {
    printf "\nPlease fix the following spelling mistakes:\n"
    # show file paths relative to repo root
    sed 's/^/* Documentation\//' "${spelldir}"/*
}

hint_about_wordlist_update() {
    new_words="$(sed -E "s/^([^:]+:){2} \(([^ ]+)\).*/\2/g" "${spelldir}"/* | sort -u | tr '\r\n' ' ' | sed "s/'/\\\\\\\\'/g")"
    printf "\nIf the words are not misspelled, run:\n%s %s\n" \
        "Documentation/update-spelling_wordlist.sh" "${new_words}"
}

if [ -n "${SKIP_LINT-}" ]; then
  echo "Skipping syntax and spelling validations..."
else
  echo "Running linter..."
  CONF_PY_ROLES=$(sed -n "/^extlinks = {$/,/^}$/ s/^ *'\([^']\+\)':.*/\1/p" conf.py | tr '\n' ',')
  CONF_PY_SUBSTITUTIONS="$(sed -n 's/^\.\. |\([^|]\+\)|.*/\1/p' conf.py | tr '\n' ',')release"
  ignored_messages="("
  ignored_messages="${ignored_messages}bpf.rst:.*: \(INFO/1\) Enumerated list start value not ordinal"
  ignored_messages="${ignored_messages}|Hyperlink target .*is not referenced\."
  ignored_messages="${ignored_messages}|Duplicate implicit target name:"
  ignored_messages="${ignored_messages}|Malformed table\."
  ignored_messages="${ignored_messages})"
  rstcheck \
      --report info \
      --ignore-language bash \
      --ignore-message "${ignored_messages}" \
      --ignore-directives tabs \
      --ignore-roles ${CONF_PY_ROLES}\
      --ignore-substitutions ${CONF_PY_SUBSTITUTIONS} \
      -r .

  echo "Validating documentation (syntax, spelling)..."
  if build_with_spellchecker ; then
    status_ok=0
    if [ -s ${warnings} ]; then
        printf "\nPlease fix the following documentation warnings:\n"
        cat ${warnings}
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
sphinx-build -M "${target}" "${script_dir}" "${build_dir}" $@ -q 2> >(tee "${warnings}" >&2)

# We can have warnings but no errors here, or sphinx-build would return non-0
# and we would have exited because of "set -o errexit".
if [ -s "${warnings}" ] ; then
    echo "Please fix the above documentation warnings"
    exit 1
fi
