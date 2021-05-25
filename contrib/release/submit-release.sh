#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 Authors of Cilium

DIR=$(dirname $(readlink -ne $BASH_SOURCE))
source $DIR/lib/common.sh
source $DIR/../backporting/common.sh

REMOTE="$(get_remote)"
BRANCH="${1:-""}"
if [ "$BRANCH" = "" ]; then
    BRANCH=$(git symbolic-ref --short HEAD | sed 's/.*\(v[0-9]\+\.[0-9]\+\).*/\1/')
fi
BRANCH=$(echo "$BRANCH" | sed 's/^v//')

RELEASE="v$(cat VERSION)"
SUMMARY=${2:-}
GENERATE_SUMMARY=false
if [ "$SUMMARY" = "" ]; then
    SUMMARY="$RELEASE-changes.txt"
    GENERATE_SUMMARY=true
fi

USER_REMOTE=$(get_user_remote ${3:-})

if ! git branch -a | grep -q "$REMOTE/v$BRANCH$" || [ ! -e $SUMMARY ]; then
    echo "usage: $0 [branch version] [release-summary] [your remote]" 1>&2
    echo 1>&2
    echo "Ensure 'branch version' is available in '$REMOTE' and the summary file exists" 1>&2
    exit 1
fi

if ! hub help | grep -q "pull-request"; then
    echo "This tool relies on 'hub' from https://github.com/github/hub." 1>&2
    echo "Please install this tool first." 1>&2
    exit 1
fi

if ! git diff --quiet; then
    echo "Local changes found in git tree. Exiting release process..." 1>&2
    exit 1
fi

if ! git log --oneline | grep -q $RELEASE; then
    echo "Latest commit does not match commit title for release:" 1>&2
    git log -1
    exit 1
fi

if $GENERATE_SUMMARY; then
    CHANGELOG=$SUMMARY
    SUMMARY="$RELEASE-pr-$(date --rfc-3339=date).txt"
    echo "Prepare for release $RELEASE" > $SUMMARY
    tail -n+4 $CHANGELOG >> $SUMMARY
fi

echo -e "Sending PR for branch v$BRANCH:\n" 1>&2
cat $SUMMARY 1>&2
echo -e "\nSending pull request..." 2>&1
PR_BRANCH=$(git rev-parse --abbrev-ref HEAD)
git push $USER_REMOTE "$PR_BRANCH"
hub pull-request -b "v$BRANCH" -l kind/release,backport/$BRANCH -F $SUMMARY
