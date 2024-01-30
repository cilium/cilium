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
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[3]}"
else
  >&2 echo "ERROR: failed to parse version '${VERSION}'"
  exit 1
fi

tag_exists() {
    local tag="refs/tags/${1}"

    # Check if the tag is already present locally.
    if git rev-parse --verify --end-of-options "${tag}" &> /dev/null; then
        return 0
    fi

    # If not, try to fetch it from origin.
    >&2 echo "INFO: tag '${tag}' not present locally, trying to fetch it from origin"
    git fetch --depth=1 origin "+${tag}:${tag}" &> /dev/null || true

    # Retry after the fetch attempt.
    if git rev-parse --verify --end-of-options "${tag}" &> /dev/null; then
        return 0
    fi

    return 1
}

print_prev_patch() {
    local version="${1}" major="${2}" minor="${3}" patch="${4}"
    local tag="v${major}.${minor}.${patch}${TAG_SUFFIX:-}"

    # If we're on the development branch, there is no previous patch release to
    # downgrade to. Calling workflow should typically skip the job.
    if [[ "${version}" =~ -dev$ ]] ; then
        >&2 echo "ERROR: no previous patch release for development version '${version}'"
        exit 1
    fi

    # In most cases, the previous patch release is in fact the same as
    # indicated in $version and we just need to return it (with TAG_SUFFIX as
    # required).

    # Hack: When working on a patch release preparation PR, file VERSION
    # contains the new value for the release that is yet to be tagged and
    # published. So if the tag does not exist, we want to downgrade to the
    # previous patch release.
    #
    # Only run this step if we're in a Git repository with a remote named
    # "origin".
    if git rev-parse --is-inside-work-tree &> /dev/null && \
        git remote | \grep -q '^origin$' ; then

        if ! tag_exists "${tag}"; then
            # If the patch version is 0, we cannot decrement it further.
            if [[ "${patch}" -le "0" ]] ; then
                >&2 echo "ERROR: failed to deduce patch release previous to version '${version}' (cannot decrement patch version)"
                exit 1
            fi

            >&2 echo "INFO: tag '${tag}' not found, assuming we're on a release preparation Pull Request: decrementing patch release number"
            tag="v${major}.${minor}.$((patch - 1))${TAG_SUFFIX:-}"

            # Note: Based on the current usage of this script in workflows, we
            # assume that the version computed by decrementing the patch number
            # exists, and we don't check for its existence here. If it does not
            # exist at this stage, the calling workflow will try to downgrade
            # to an inexistent version and fail loudly, which is the desired
            # behaviour.
        fi
    fi

    echo "${tag}"
}

print_prev_branch() {
    local version="${1}" major="${2}" minor="${3}"

    # If the minor version is 0, we cannot decrement it further.
    if [[ "${minor}" == "0" ]] ; then
        >&2 echo "ERROR: failed to deduce release previous to version '${version}' (cannot decrement minor version number)"
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
    print_prev_patch "${VERSION}" "${MAJOR}" "${MINOR}" "${PATCH}"
else
    print_prev_branch "${VERSION}" "${MAJOR}" "${MINOR}"
fi
