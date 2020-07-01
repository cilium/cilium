#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

RELEASE_TOOL_PATH="${RELEASE_TOOL_PATH:-$GOPATH/src/github.com/cilium/release}"
RELNOTES="$RELEASE_TOOL_PATH/release"
RELNOTESCACHE="release-state.json"

usage() {
    logecho "usage: $0 <OLD-VERSION> <NEW-VERSION>"
    logecho "OLD-VERSION    Previous release version for comparison"
    logecho "NEW-VERSION    Target release version"
    logecho
    logecho "--help     Print this help message"
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

    if ! echo "$1" | grep -q "[0-9]\+\.[0-9]\+\.[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid OLD-VERSION ARG \"$1\"; Expected X.Y.Z"
    fi

    if ! echo "$2" | grep -q "[0-9]\+\.[0-9]\+\.[0-9]\+[-rc0-9]*"; then
        usage 2>&1
        common::exit 1 "Invalid NEW-VERSION ARG \"$1\"; Expected X.Y.Z[-rcW]"
    fi
}

main() {
    handle_args "$@"

    local old_version="$(echo $1 | sed 's/^v//')"
    local ersion="$(echo $2 | sed 's/^v//')"
    local version="v$ersion"

    logecho "Generating CHANGELOG.md"
    rm -f $RELNOTESCACHE
    echo -e "# Changelog\n\n## $version" > $version-changes.txt
    $RELNOTES --base $old_version --head $(git rev-parse HEAD) >> $version-changes.txt
    cp $version-changes.txt CHANGELOG-new.md
    if [[ -e CHANGELOG.md ]]; then
        tail -n+2 CHANGELOG.md >> CHANGELOG-new.md
    fi
    mv CHANGELOG-new.md CHANGELOG.md
    logecho "Generated CHANGELOG.md"
}

main "$@"
