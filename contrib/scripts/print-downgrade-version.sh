#!/usr/bin/env bash
#
# A utility script to print the branch name of the previous stable or patch
# release.
#
# The script returns the estimated branch or tag name for the version to
# downgrade to. If it cannot determine this value, it returns nothing (and
# prints a message to stderr). It belongs to the calling workflow to determine
# whether an empty value should lead to an error or to skipping parts of a CI
# job.

set -o errexit
set -o nounset

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VERSION="${VERSION-"$(cat "${SCRIPT_DIR}/../../VERSION")"}"
if [[ "${VERSION}" =~ ([0-9^]+)\.([0-9^]+)\.([0-9^]+).* ]] ; then
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    patch="${BASH_REMATCH[3]}"
else
  >&2 echo "ERROR: failed to parse version '${VERSION}'"
  exit 1
fi

print_prev_patch() {
    # If we're on the development branch, there is no previous patch release to
    # downgrade to. Calling workflow should typically skip the job.
    if [[ "${VERSION}" =~ -dev$ ]] ; then
        >&2 echo "ERROR: no previous patch release for development version '${VERSION}'"
        exit 1
    fi

    # In most cases, the previous patch release is in fact the same as
    # indicated in VERSION and we just need to return it (with TAG_SUFFIX as
    # required).

    # Hack: When working on a patch release preparation commit, file VERSION
    # contains the new value for the release that is yet to be tagged and
    # published. In this case, we want to downgrade to the previous patch
    # release.
    #
    # Only run this step if we're in a Git repository, and we have more than
    # one commit in the repo (otherwise, we're likely on a shallow clone).
    # This means CI workflows relying on a previous patch release and calling
    # this script should download at least part of the history, with
    # "fetch-depth: 2".
    if git rev-parse --is-inside-work-tree &> /dev/null && \
        git rev-parse --verify HEAD^ &> /dev/null && \
        git diff --name-only HEAD^..HEAD | grep -q "^VERSION$"; then
        # If the patch version is 0, we cannot decrement it further.
        if [[ "${patch}" -le "0" ]] ; then
            >&2 echo "ERROR: failed to deduce patch release previous to version '${VERSION}'"
            exit 1
        fi
        patch=$((patch - 1))
    fi

    echo "v${major}.${minor}.${patch}${TAG_SUFFIX:-}"
}

print_prev_branch() {
    # If the minor version is 0, we cannot decrement it further.
    if [[ "${minor}" == "0" ]] ; then
        >&2 echo "ERROR: failed to deduce release previous to version '${VERSION}'"
        exit 1
    fi

    # Print the previous stable version by decrementing the minor version and
    # trimming the patch version.
    minor=$((minor - 1))
    echo "v${major}.${minor}${BRANCH_SUFFIX:-}"
}

# If user passed "patch" as first argument, print the latest patch version.
# Otherwise, print the latest stable version.
if [[ ${1-} == "patch" ]] ; then
    print_prev_patch
else
    print_prev_branch
fi
