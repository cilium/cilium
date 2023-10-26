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
    case ${patch} in
        0|90)
            # Patch release number 90 is used for preparing releases.
            >&2 echo "ERROR: failed to deduce patch release previous to version '$VERSION'"
            exit 1
            ;;
        *)
            ((patch--))
            echo "v${major}.${minor}.${patch}${TAG_SUFFIX:-}"
            ;;
    esac
else
    # Else print the previous stable version by decrementing the minor version
    # and trimming the patch version.
    ((minor--))
    echo "v${major}.${minor}${BRANCH_SUFFIX:-}"
fi
