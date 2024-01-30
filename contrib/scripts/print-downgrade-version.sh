#!/usr/bin/env bash
#
# A utility script to print the branch name of the previous stable or patch
# release.

set -o errexit
set -o nounset

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VERSION=${VERSION-"$(cat "$SCRIPT_DIR/../../VERSION")"}
if [[ $VERSION =~ ([0-9^]+)\.([0-9^]+)\.([0-9^]+).* ]] ; then
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}
    patch=${BASH_REMATCH[3]}
else
  >&2 echo "ERROR: failed to parse version '$VERSION'"
  exit 1
fi

if [[ ${1-} == "patch" ]] ; then
    # If user passed "patch" as first argument, print the latest patch version

    if [[ "${patch}" -le "0" ]] ; then
        >&2 echo "ERROR: failed to deduce patch release previous to version '$VERSION'"
        exit 1
    fi

    tag="v${major}.${minor}.${patch}${TAG_SUFFIX:-}"

    # Hack: When working on a patch release preparation commit, file VERSION
    # contains the new value for the release that is yet to be tagged and
    # published. So if the tag does not exist, we want to downgrade to the
    # previous patch release.
    #
    # Only run this step if we're in a Git repository, and we have tag v1.0.0
    # in the repo (otherwise, we're likely on a shallow clone, with no tags
    # fetched).
    if git rev-parse --is-inside-work-tree &> /dev/null && \
        git rev-parse --verify --end-of-options v1.0.0 &> /dev/null && \
        ! git rev-parse --verify --end-of-options "${tag}" &> /dev/null; then
        >&2 echo "INFO: tag ${tag} not found, decrementing patch release number"
        patch=$((patch - 1))
        tag="v${major}.${minor}.${patch}${TAG_SUFFIX:-}"
    fi
    echo "${tag}"
else
    if [[ "${minor}" == "0" ]] ; then
        >&2 echo "ERROR: failed to deduce release previous to version '$VERSION'"
        exit 1
    fi
    # Else print the previous stable version by decrementing the minor version
    # and trimming the patch version.
    ((minor--))
    echo "v${major}.${minor}${BRANCH_SUFFIX:-}"
fi
