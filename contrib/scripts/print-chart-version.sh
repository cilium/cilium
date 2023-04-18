#!/usr/bin/env bash
# shellcheck disable=SC2001

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

VERSION="$(cat "$SCRIPT_DIR/../../VERSION")"
GIT_COMMIT_COUNT="$(git rev-list --count "$(git log --follow -1 --pretty=%H VERSION)"..HEAD)"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
GIT_BRANCH_SANITIZED="$(echo "${GIT_BRANCH}" | sed 's/[^[:alnum:]]/-/g' )"
GIT_HASH="$(git rev-parse --short HEAD)"
CHART_VERSION_PRERELEASE_PREFIX=dev
CHART_VERSION_DEV="${VERSION}-${CHART_VERSION_PRERELEASE_PREFIX}.${GIT_COMMIT_COUNT}+${GIT_BRANCH_SANITIZED}-${GIT_HASH}"
# Using an OCI repository for helm means versions are stored as OCI tags, which cannot contain +.
# Using _ isn't valid either, because helm chart versions must be semver compatible.
# No v prefix for the chart version.
CHART_VERSION=$(echo "${CHART_VERSION_DEV}" | sed 's/+/-/g')

echo "${CHART_VERSION}"
