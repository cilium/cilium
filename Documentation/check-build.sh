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
root_dir="$(dirname "${script_dir}")"

build_dir="${script_dir}/_build"
warnings="${build_dir}/warnings.txt"
spelldir="${build_dir}/spelling"
redirect_warnings="${build_dir}/redirect-warnings.txt"
redirectdir="${build_dir}/redirect"

target="${1:-"html"}"
shift

cd "${script_dir}"
mkdir -p "${build_dir}"
rm -f -- "${warnings}" "${redirect_warnings}"

has_spelling_errors() {
    # If spelling errors were found, Sphinx wrote them to files under
    # ${spelldir}. Let's check whether the directory is empty.
    test -n "$(ls "${spelldir}" 2>/dev/null)"
}

# Filter out some undesirable warnings
filter_warnings() {
    test -s "${warnings}" || return
    cat "${warnings}"
}

# Returns non-0 if we have relevant build warnings
has_build_warnings() {
    test -s "${warnings}"
}

describe_spelling_errors() {
    local new_words

    # Show all misspelled words; display source path relative to root repository
    find "${spelldir}" -type f -print0 | xargs -0 sed 's/^/* Documentation\//'

    # Print a hint on how to add new correct words to the list of good words
    new_words="$(find "${spelldir}" -type f -print0 | \
        xargs -0 sed -E "s/^([^:]+:){2} \(([^ ]+)\).*/\2/g" | \
        sort -u | \
        tr '\r\n' ' ' | \
        sed "s/'/\\\\\\\\'/g")"
    printf "\nIf the words are not misspelled, run:\n%s %s\n" \
        "Documentation/update-spelling_wordlist.sh" "${new_words}"
}

# Returns non-0 if we have relevant redirect warnings
has_redirect_errors() {
    test -s "${redirect_warnings}"
}

describe_redirect_errors() {
    cat "${redirect_warnings}"

    printf "\nTip, try running:\nmake -C Documentation update-redirects\n"
}

build_with_spellchecker() {
    # The spell checker runs some Git commands to retrieve the name of authors
    # and consider them as acceptable words.
    #
    # Recent Git versions refuse to work by default if the repository owner is
    # different from the user. This is the case when we run this script in a
    # container on macOS, because pass --user "uid:gid", and these values
    # differ from what Linux is used to (The gid from macOS seems to be 20,
    # which corresponds to the "dialout" group in the container). We pass
    # --user "uid:gid" to have the "install" command work in the workaround for
    # versionwarning above.
    #
    # If running in a container, tell Git that the repository is safe.
    set +o nounset
    if [[ -n "$MAKE_GIT_REPO_SAFE" ]]; then
        export GIT_CONFIG_COUNT=1
        export GIT_CONFIG_KEY_0=safe.directory
        export GIT_CONFIG_VALUE_0="${root_dir}"
    fi
    set -o nounset
    rm -rf "${spelldir}"
    # Call with -W --keep-going: suppresses regular output (keeps warning;
    # -Q would suppress warnings as well including those we write to a file),
    # consider warnings as errors for exit status, but keep going on
    # warning/errors so that we get the full list of errors.
    sphinx-build -b spelling \
        -d "${build_dir}/doctrees" . "${spelldir}" \
        -E -n --color -w "${warnings}" -W --keep-going 2>/dev/null
}

build_with_redirectchecker() {
    # The redirect checker runs some Git commands to determine which files have
    # moved and been deleted so it can generate and check for missing
    # redirects.
    #
    # Recent Git versions refuse to work by default if the repository owner is
    # different from the user. This is the case when we run this script in a
    # container on macOS, because pass --user "uid:gid", and these values
    # differ from what Linux is used to (The gid from macOS seems to be 20,
    # which corresponds to the "dialout" group in the container). We pass
    # --user "uid:gid" to have the "install" command work in the workaround for
    # versionwarning above.
    #
    # If running in a container, tell Git that the repository is safe.
    set +o nounset
    if [[ -n "$MAKE_GIT_REPO_SAFE" ]]; then
        export GIT_CONFIG_COUNT=1
        export GIT_CONFIG_KEY_0=safe.directory
        export GIT_CONFIG_VALUE_0="${root_dir}"
    fi
    set -o nounset
    rm -rf "${redirectdir}"
    # Call with -W --keep-going: suppresses regular output (keeps warning;
    # -Q would suppress warnings as well including those we write to a file),
    # consider warnings as errors for exit status, but keep going on
    # warning/errors so that we get the full list of errors.
    sphinx-build -b rediraffecheckdiff \
        -d "${build_dir}/doctrees" . "${redirectdir}" \
        -E -n --color -w "${redirect_warnings}" -W --keep-going 2>/dev/null
}

run_checks() {
    code=0
    echo "Running spellcheck"
    if ! build_with_spellchecker; then
      echo "spellcheck failed"
      code=1
    fi
    echo "Running redirect check"
    if ! build_with_redirectchecker; then
      echo "redirect check failed"
      code=1
    fi
    return $code
}

run_linter() {
    local CONF_PY_ROLES CONF_PY_SUBSTITUTIONS ignored_messages

    CONF_PY_ROLES=$(sed -n "/^extlinks = {$/,/^}$/ s/^ *'\([^']\+\)':.*/\1/p" conf.py | tr '\n' ',')
    CONF_PY_SUBSTITUTIONS="$(sed -n 's/^\.\. |\([^|]\+\)|.*/\1/p' conf.py | tr '\n' ',')release"
    CONF_PY_TARGET_NAMES="(cilium slack)"
    ignored_messages="("
    ignored_messages="${ignored_messages}bpf/.*\.rst:.*: \(INFO/1\) Enumerated list start value not ordinal"
    ignored_messages="${ignored_messages}|Hyperlink target .*is not referenced\."
    ignored_messages="${ignored_messages}|Duplicate implicit target name:"
    ignored_messages="${ignored_messages}|\(ERROR/3\) Indirect hyperlink target \".*\"  refers to target \"${CONF_PY_TARGET_NAMES}\", which does not exist."
    ignored_messages="${ignored_messages}|\(ERROR/3\) Unknown target name: \"${CONF_PY_TARGET_NAMES}\"."
    ignored_messages="${ignored_messages})"
    # Filter out the AttributeError reports that are due to a bug in rstcheck,
    # see https://github.com/rstcheck/rstcheck-core/issues/3.
    rstcheck \
        --report-level info \
        --ignore-languages "bash,c" \
        --ignore-messages "${ignored_messages}" \
        --ignore-directives "tabs,openapi" \
        --ignore-roles "${CONF_PY_ROLES},spelling:ignore,spelling:word" \
        --ignore-substitutions "${CONF_PY_SUBSTITUTIONS}" \
       -r . ../README.rst 2>&1 | \
       grep -v 'WARNING:rstcheck_core.checker:An `AttributeError` error occurred. This is most probably due to a code block directive (code/code-block/sourcecode) without a specified language.'
}

read_all_opt=""

if [ -n "${SKIP_LINT-}" ]; then
  if [ -z "${INCREMENTAL-}" ]; then
    # Read all files for final build if we don't read them all with linting
    read_all_opt="-E"
  fi

  echo ""
  echo "Skipping syntax and spelling validations..."
else
  echo ""
  echo "Running linter..."
  run_linter

  echo ""
  echo "Validating documentation (syntax, spelling, redirects)..."

  if ! run_checks; then
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

    if has_redirect_errors ; then
        printf "\nPlease fix the following missing redirects:\n"
        describe_redirect_errors
        status_ok=1
    fi

    if [ "${status_ok}" -ne 0 ] ; then
        exit 1
    fi
  fi
fi

echo "Building documentation (${target})..."
sphinx-build -M "${target}" "${script_dir}" "${build_dir}" $@ \
    ${read_all_opt} -n --color -w "${warnings}" 2>/dev/null

# We can have warnings but no errors here, or sphinx-build would return non-0
# and we would have exited because of "set -o errexit".
if has_build_warnings ; then
    echo "Please fix the documentation warnings below"
    filter_warnings
    exit 1
fi
