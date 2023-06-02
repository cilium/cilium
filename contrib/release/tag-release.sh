#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

REMOTE="$(get_remote)"
CHARTS_PATH="${CHARTS_PATH:-$GOPATH/src/github.com/cilium/charts}"
CHARTS_TOOL="prepare_artifacts.sh"
RELEASES_URL="https://github.com/cilium/cilium/releases"
VERSION=""

usage() {
    echo "usage: $0 [VERSION]"
    echo "CHARTS_REPO Path to local copy of github.com/cilium/charts"
    echo
    echo "--help     Print this help message"
}

handle_args() {
    if [[ "$1" = "--help" ]] || [[ "$1" = "-h" ]]; then
        usage
        common::exit 1
    fi

    if [[ ! -e VERSION ]]; then
        common::exit 1 "VERSION file not found. Is this directory a Cilium repository?"
    fi

    if [[ ! -e "$CHARTS_PATH/$CHARTS_TOOL" ]]; then
        usage
        common::exit 1 "CHARTS_PATH='$CHARTS_PATH' invalid. Clone from github.com/cilium/charts"
    fi

    if ! which hub >/dev/null; then
        echo "This tool relies on 'hub' from https://github.com/github/hub ." 1>&2
        common::exit 1 "Please install this tool first."
    fi

    if [[ $# -ge 1 ]]; then
        VERSION="$1"
    fi
}

main() {
    handle_args "$@"

    local ersion="$(cat VERSION)"
    if [[ "$VERSION" != "" ]]; then
        ersion="$(echo $VERSION | sed 's/^v//')"
    fi
    local version="v$ersion"

    if [[ ! -e $version-changes.txt ]]; then
        common::exit 1 "Generate release notes via contrib/release/start-release.sh"
    fi

    git fetch $REMOTE

    local commit="$(git rev-parse HEAD)"
    BRANCH="$(get_branch_from_version $REMOTE $(git symbolic-ref -q --short HEAD))"
    echo "Current HEAD is:"
    git log --oneline -1 "$commit"
    if ! commit_in_upstream "$commit" "$BRANCH"; then
        common::exit 1 "Commit $commit not in $REMOTE/$BRANCH!"
    fi

    echo "Create git tags for $version with this commit"
    if ! common::askyorn ; then
        common::exit 0 "Aborting release preparation."
    fi

    logrun -s git tag -a $ersion -s -m "Release $version"
    logrun -s git tag -a $version -s -m "Release $version"
    logrun -s git push $REMOTE $version $ersion

    # Leave $version-changes.txt around so we can generate release notes later
    echo -e "$ersion\n" > $version-release-summary.txt
    echo "We are pleased to release Cilium $version." >>  $version-release-summary.txt
    tail -n+4 $version-changes.txt >> $version-release-summary.txt
    logecho "Creating Github draft release"
    logrun hub release create -d -F $version-release-summary.txt $version
    logecho "Browse to $RELEASES_URL to see the draft release"

    logecho
    logecho "Next steps:"
    logecho "* Wait for cilium docker images to be prepared"
    logecho "* Prepare the helm template changes"
    logecho "* When docker images are available, test deployment of new version"
    logecho "* Push templates and announce release on GitHub / Slack"
}

main "$@"
