#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

RELEASE_TOOL_PATH="${RELEASE_TOOL_PATH:-$GOPATH/src/github.com/cilium/release}"
RELNOTES="$RELEASE_TOOL_PATH/release"
RELNOTESCACHE="release-state.json"

usage() {
    logecho "usage: $0 <OLD-VERSION> <NEW-VERSION> [OLD-BRANCH]"
    logecho "OLD-VERSION    Previous release version for comparison"
    logecho "NEW-VERSION    Target release version"
    logecho "OLD-BRANCH     Branch of the previous release version if VERSION is "
    logecho "               a new minor version"
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

    if ! echo "$1" | grep -q "$RELEASE_REGEX"; then
        usage 2>&1
        common::exit 1 "Invalid OLD-VERSION ARG \"$1\"; Expected X.Y.Z[-rc.W|-snapshot.W]"
    fi

    if ! echo "$2" | grep -q "$RELEASE_REGEX"; then
        usage 2>&1
        common::exit 1 "Invalid NEW-VERSION ARG \"$2\"; Expected X.Y.Z[-rc.W|-snapshot.W]"
    fi

    if [ "$#" -eq 3 ] && ! echo "$3" | grep -q "[0-9]\+\.[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid OLD-BRANCH ARG \"$3\"; Expected X.Y"
    fi
}

main() {
    handle_args "$@"

    local old_version="$(echo $1 | sed 's/^v//')"
    local ersion="$(echo $2 | sed 's/^v//')"
    local version="v$ersion"
    local old_branch="$(echo $3 | sed 's/^v//')"

    logecho "Generating CHANGELOG.md"
    rm -f $RELNOTESCACHE
    echo -e "# Changelog\n\n## $version" > $version-changes.txt
    if [ "${old_branch}" = "" ] ; then
      $RELNOTES --base $old_version --head $(git rev-parse HEAD) >> $version-changes.txt
    else
      $RELNOTES --last-stable $old_branch --base $old_version --head $(git rev-parse HEAD) >> $version-changes.txt
    fi
    cp $version-changes.txt CHANGELOG-new.md
    if [[ -e CHANGELOG.md ]]; then
        tail -n+2 CHANGELOG.md >> CHANGELOG-new.md
    fi
    mv CHANGELOG-new.md CHANGELOG.md
    logecho "Generated CHANGELOG.md"
}

main "$@"
