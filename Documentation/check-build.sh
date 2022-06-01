#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# This was ported from the makefile, it can probably be converted
# to Python (see e.g. https://stackoverflow.com/a/47657926), that
# way we might be able to call Sphinx only once and make it quicker
# Update 2022-05: It seems that Sphinx cannot run multiple builders
# (e.g. html + spelling) at once so we're stuck calling it multiple
# times anyway.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_dir="${script_dir}/_build"
warnings="${build_dir}/warnings.txt"
spelldir="${build_dir}/spelling"

target="${1:-"html"}"
shift

cd "${script_dir}"
mkdir -p "${build_dir}"
rm -f -- "${warnings}"

has_spelling_errors() {
    # If spelling errors were found, Sphinx wrote them to files under
    # ${spelldir}. Let's check whether the directory is empty.
    test -n "$(ls "${spelldir}")"
}

# Filter out some undesirable warnings:
#   - Spelling (we already have individual warnings for each word)
filter_warnings() {
    [ -s "${warnings}" ] || return
    grep -v -E \
        -e 'Found .* misspelled words' \
        -e "/_api/v1/.*/README\.md:[0-9]+: WARNING: 'myst' reference target not found:" \
        "${warnings}"
}

# Returns non-0 if we have relevant build warnings
has_build_warnings() {
    filter_warnings > /dev/null
}

describe_spelling_errors() {
    local new_words

    # Show all misspelled words; display source path relative to root repository
    find "${spelldir}" -type f -print0 | xargs -0 sed 's/^/* Documentation\//'

    # Print a hint on how to add new correct words to the list of good words
    new_words="$(sed -E "s/^([^:]+:){2} \(([^ ]+)\).*/\2/g" "${spelldir}"/* | sort -u | tr '\r\n' ' ' | sed "s/'/\\\\\\\\'/g")"
    printf "\nIf the words are not misspelled, run:\n%s %s\n" \
        "Documentation/update-spelling_wordlist.sh" "${new_words}"
}

build_with_spellchecker() {
    rm -rf "${spelldir}"
    # Call with -q -W --keep-going: suppresses regular output (keeps warning;
    # -Q would suppress warnings as well including those we write to a file),
    # consider warnings as errors for exit status, but keep going on
    # warning/errors so that we get the full list of errors.
    sphinx-build -b spelling \
        -d "${build_dir}/doctrees" . "${spelldir}" \
        -E -n --color -q -w "${warnings}" -W --keep-going 2>/dev/null
}

build_with_linkchecker() {
    sphinx-build -b linkcheck -d "${build_dir}/doctrees" . "${spelldir}" -q -E
}

run_linter() {
    local CONF_PY_ROLES CONF_PY_SUBSTITUTIONS ignored_messages

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
        --ignore-roles "${CONF_PY_ROLES}" \
        --ignore-substitutions "${CONF_PY_SUBSTITUTIONS}" \
        -r .
}

read_all_opt=""

if [ -n "${SKIP_LINT-}" ]; then
  # Read all files for final build if we don't read them all with linting
  read_all_opt="-E"

  echo "Skipping syntax and spelling validations..."
else
  echo "Running linter..."
  run_linter

  echo "Validating documentation (syntax, spelling)..."
  if ! build_with_spellchecker ; then
    status_ok=0
    if has_build_warnings ; then
        printf "\nPlease fix the following documentation warnings:\n"
        filter_warnings
        status_ok=1
    fi

    if has_spelling_errors ; then
        printf "\nPlease fix the following spelling mistakes:\n"
        describe_spelling_errors
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
sphinx-build -M "${target}" "${script_dir}" "${build_dir}" $@ \
    ${read_all_opt} -n --color -q -w "${warnings}" 2>/dev/null

# We can have warnings but no errors here, or sphinx-build would return non-0
# and we would have exited because of "set -o errexit".
if has_build_warnings ; then
    echo "Please fix the documentation warnings below"
    filter_warnings
    exit 1
fi
