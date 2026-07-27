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
#
# To some extent, this script is taylored for Cilium's CI workflows, and is
# probably not something you want to run for other purposes.
#
# Usage:
#
#   $ print-downgrade-version.sh <stable|patch>
#
# With "stable", the script prints the branch name of the previous stable
# branch. With "patch", it attempts to find out the tag of the latest patch
# release for the current branch.
#
# The version for the previous branch is computed by decrementing the minor
# version number for the current branch, based on the value in VERSION.
#
# The version for the latest patch release is computed as follows:
#
# - Error out on the development branch (if the VERSION ends with "-dev").
# - If the value in VERSION corresponds to an existing tag, return this value.
# - If the value in VERSION does not correspond to an existing tag, assume we
#   are on a release preparation Pull Request and attempt to compute the
#   previous patch release by decrementing the patch release version.
#
# Environment variables:
#
# - VERSION: The version supposed to be in the VERSION file at the root of the
#   repository. For testing purposes.
# - BRANCH_SUFFIX: A suffix to append to the generated branch name, when
#   downgrading to the lower stable branch.
# - TAG_SUFFIX: A suffix to append to the generated tag name, when downgrading
#   to the latest patch release, provided the script does not simply reuse the
#   value in VERSION.

set -o errexit
set -o nounset

usage() {
    >&2 echo "Usage: $0 <stable|patch>"
    exit 1
}

if [[ "$#" -ne 1 ]]; then
    usage
fi
case "${1}" in
    stable|patch)
        ;;
    *)
        usage
        ;;
esac

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
    #
    # Note: Stuff we tried before in the past (for the patch release case),
    # instead of calling "git fetch" in this script:
    #
    # - Downloading the tags directly in the CI workflow YAML file, by passing
    #   "fetch-tags: true" to the checkout Action. This does not work with
    #   shallow clones, only the tags pointing to objects present in the clone
    #   are fetched.
    # - Setting "fetch-depth: 2" in the workflow to fetch two commits: the
    #   latest commit on top of a commit that squashes all the rest of the
    #   history. Then we can check whether the latest commit updates VERSION,
    #   and assume we're on a release preparation PR in that case. This does
    #   not work well, however, if the release manager pushes additional fixes
    #   on top of the prep commit.
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
    local tag

    # If we're on the development branch, there is no previous patch release to
    # downgrade to. Calling workflow should typically skip the job.
    if [[ "${version}" =~ -dev$ ]] ; then
        >&2 echo "ERROR: no previous patch release for development version '${version}'"
        exit 1
    fi

    # In most cases, the previous patch release is in fact the same as
    # indicated in $version and we just need to return it.
    # Note that we still prefix it with "v" to match the tag format.
    # Also note that in this case, we assume that VERSION already contains any
    # TAG_SUFFIX that would be required, and we do not append the content from
    # the environment variable.
    local tag="v${VERSION}"

    # Hack: When working on a patch release preparation PR, file VERSION
    # contains the new value for the release that is yet to be tagged and
    # published. So if the tag does not exist, we want to downgrade to the
    # previous patch release, by computing the (assumed) previous tag value.
    #
    # Only run this step if we're in a Git repository with a remote named
    # "origin".
    if git rev-parse --is-inside-work-tree &> /dev/null && \
        git remote | grep -q '^origin$' ; then

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
if [[ ${1} == "patch" ]] ; then
    print_prev_patch "${VERSION}" "${MAJOR}" "${MINOR}" "${PATCH}"
else
    print_prev_branch "${VERSION}" "${MAJOR}" "${MINOR}"
fi
