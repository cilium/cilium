#!/usr/bin/env bash
#
# A utility script to print the branch name of the previous stable release.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VERSION="$(cat "$SCRIPT_DIR/../../VERSION")"
if [[ $VERSION =~ ([0-9^]+)\.([0-9^]+)\..* ]] ; then
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}
    ((minor--))
    echo "v${major}.${minor}${BRANCH_SUFFIX:-}"
else
  echo "ERROR: failed to parse version '$VERSION'"
  exit 1
fi
