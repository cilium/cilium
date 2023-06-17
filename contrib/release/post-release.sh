#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source "${DIR}/lib/common.sh"
source "${DIR}/../backporting/common.sh"

usage() {
    logecho "usage: $0 <RUN-URL> [VERSION] [GH-USERNAME]"
    logecho "RUN-URL      GitHub URL with the RUN for the release images"
    logecho "             example: https://github.com/cilium/cilium/actions/runs/600920964"
    logecho "VERSION      Target version (X.Y.Z) (default: read from VERSION file)"
    logecho "GH-USERNAME  GitHub username for authentication (default: autodetect)"
    logecho "GITHUB_TOKEN environment variable set with the scope public:repo"
    logecho
    logecho "--help     Print this help message"
}

handle_args() {
    if ! common::argc_validate 4; then
        usage 2>&1
        common::exit 1
    fi

    if [[ "$1" = "--help" ]] || [[ "$1" = "-h" ]] || [[ $# -lt 1 ]]; then
        usage
        common::exit 0
    fi

    if ! hub help | grep -q "pull-request"; then
        echo "This tool relies on 'hub' from https://github.com/github/hub." 1>&2
        echo "Please install this tool first." 1>&2
        common::exit 1
    fi

    if ! git diff --quiet; then
        echo "Local changes found in git tree. Exiting release process..." 1>&2
        exit 1
    fi

    if ! echo "$1" | grep -q ".*github.com.*actions.*"; then
        echo "Invalid URL. The URL must be the overall actions page, not one specific run." 1>&2
        exit 1
    fi

    if [ ! -z "$2" ] && ! echo "$2" | grep -q "[0-9]\+\.[0-9]\+\.[0-9]\+"; then
        usage 2>&1
        common::exit 1 "Invalid VERSION ARG \"$2\"; Expected X.Y.Z"
    fi

    if [ -z "${GITHUB_TOKEN}" ]; then
        usage 2>&1
        common::exit 1 "GITHUB_TOKEN not set!"
    fi
}

main() {
    handle_args "$@"
    local ersion version branch user_remote
    ersion="$(echo ${2:-$(cat VERSION)} | sed 's/^v//')"
    version="v${ersion}"
    branch=$(echo $version | sed 's/.*v\([0-9]\+\.[0-9]\+\).*/\1/')
    user_remote=$(get_user_remote ${3:-})

    git checkout -b pr/$version-digests $version
    ${DIR}/pull-docker-manifests.sh "$@"
    if grep -q update-helm-values Documentation/Makefile; then
        logrun make -C Documentation update-helm-values
    fi
    logecho
    logecho "Check that the following changes look correct:"
    # TODO: Make this less interactive when we have used it enough
    git add --patch install/kubernetes Documentation/
    git commit -se -m "install: Update image digests for $version" -m "Generated from $1." -m "$(cat digest-$version.txt)"
    echo "Create PR for v$branch with these changes"
    if ! common::askyorn ; then
        common::exit 0 "Aborting post-release updates."
    fi
    logecho "Sending pull request for branch v$branch..."
    PR_BRANCH=$(git rev-parse --abbrev-ref HEAD)
    git push $user_remote "$PR_BRANCH"
    hub pull-request -b "v$branch" -l backport/$branch
}

main "$@"
