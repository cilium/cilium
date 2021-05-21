#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

PROJECTS_REGEX='s/.*projects\/\([0-9]\+\).*/\1/'
ACTS_YAML=".github/maintainers-little-helper.yaml"
REMOTE="$(get_remote)"

usage() {
    logecho "usage: $0 <VERSION> <GH-PROJECT> [OLD-BRANCH]"
    logecho "VERSION    Target release version (format: X.Y.Z)"
    logecho "GH-PROJECT Project Number for next (X.Y.Z+1) development release"
    logecho "OLD-BRANCH Branch of the previous release version if VERSION is "
    logecho "           a new minor version"
    logecho
    logecho "--help     Print this help message"
}

handle_args() {
    if [ "$#" -gt 3 ]; then
        usage 2>&1
        common::exit 1
    fi

    if [[ "$1" = "--help" ]] || [[ "$1" = "-h" ]]; then
        usage
        common::exit 0
    fi

    if ! echo "$1" | grep -q "[0-9]\+\.[0-9]\+\.[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid VERSION ARG \"$1\"; Expected X.Y.Z"
    fi

    if ! echo "$2" | grep -q "^[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid GH-PROJECT ID argument. Expected [0-9]+"
    fi

    if [[ ! -e VERSION ]]; then
        common::exit 1 "VERSION file not found. Is this directory a Cilium repository?"
    fi

    if [[ "$(git status -s | grep -v "^??" | wc -l)" -gt 0 ]]; then
        git status -s | grep -v "^??"
        common::exit 1 "Unmerged changes in tree prevent preparing release PR."
    fi
}

main() {
    handle_args "$@"

    local ersion="$(echo $1 | sed 's/^v//')"
    local version="v$ersion"
    local branch="v$(echo $ersion | sed 's/[^0-9]*\([0-9]\+\.[0-9]\+\).*/\1/')"
    local new_proj="$2"
    local old_branch="$3"

    git fetch $REMOTE
    local old_version="$(cat VERSION)"

    logecho "Updating VERSION, AUTHORS.md, $ACTS_YAML, helm templates"
    echo $ersion > VERSION
    sed -i 's/"[^"]*"/""/g' install/kubernetes/Makefile.digests
    logrun make -C install/kubernetes all USE_DIGESTS=false
    old_proj=$(grep "projects" $ACTS_YAML | sed "$PROJECTS_REGEX")
    sed -i 's/\(projects\/\)[0-9]\+/\1'$new_proj'/g' $ACTS_YAML

    if [ "${old_branch}" != "" ]; then
      $DIR/prep-changelog.sh "$old_version" "$version" "$old_branch"
    else
      $DIR/prep-changelog.sh "$old_version" "$version"
    fi

    logecho "Next steps:"
    logecho "* Check all changes and add to a new commit"
    logecho "* Push the PR to Github for review ('submit-release.sh')"
    logecho "* Close https://github.com/cilium/cilium/projects/$old_proj"
    logecho "* (After PR merge) Use 'tag-release.sh' to prepare tags/release"

    # Leave $version-changes.txt around for prep-release.sh usage later
}

main "$@"
