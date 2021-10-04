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
    logecho "usage: $0 <VERSION> <GH-PROJECT>"
    logecho "VERSION    Target release version (format: X.Y.Z)"
    logecho "GH-PROJECT Project Number for next (X.Y.Z+1) development release"
    logecho
    logecho "--help     Print this help message"
}

# $1 - VERSION
version_is_prerelease() {
    case "$1" in
        *rc*|*snapshot*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

handle_args() {
    if ! common::argc_validate 2; then
        usage 2>&1
        common::exit 1
    fi

    if [[ "$1" = "--help" ]] || [[ "$1" = "-h" ]]; then
        usage
        common::exit 0
    fi

    if ! echo "$1" | grep -q "$RELEASE_REGEX"; then
        usage 2>&1
        common::exit 1 "Invalid VERSION ARG \"$1\"; Expected X.Y.Z"
    fi

    if ! echo "$2" | grep -q "^[0-9]\+" && ! version_is_prerelease "$1"; then
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
    local branch="$(get_branch_from_version $REMOTE $version)"
    local new_proj="$2"
    local old_version=""

    git fetch -q $REMOTE
    if [ "$branch" = "master" ]; then
        git checkout -b pr/prepare-$version $REMOTE/$branch
        local old_branch="$(get_branch_from_version $REMOTE v$(cat VERSION))"
        old_version="$(git show $old_branch:VERSION)"
    else
        git checkout -b pr/prepare-$version $REMOTE/$branch
        old_version="$(cat VERSION)"
    fi

    logecho "Updating VERSION, AUTHORS.md, $ACTS_YAML, helm templates"
    echo $ersion > VERSION
    sed -i 's/"[^"]*"/""/g' install/kubernetes/Makefile.digests
    logrun make -C install/kubernetes all USE_DIGESTS=false
    logrun make update-authors
    if ! version_is_prerelease "$version"; then
        old_proj=$(grep "projects" $ACTS_YAML | sed "$PROJECTS_REGEX")
        sed -i 's/\(projects\/\)[0-9]\+/\1'$new_proj'/g' $ACTS_YAML
    fi

    $DIR/prep-changelog.sh "$old_version" "$version"

    logecho "Next steps:"
    logecho "* Check all changes and add to a new commit"
    logecho "  * If this is a prerelease, create a revert commit"
    logecho "* Push the PR to Github for review ('submit-release.sh')"
    logecho "* Close https://github.com/cilium/cilium/projects/$old_proj"
    logecho "* (After PR merge) Use 'tag-release.sh' to prepare tags/release"

    # Leave $version-changes.txt around for prep-release.sh usage later
}

main "$@"
