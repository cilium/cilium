#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -e

RELEASE_REGEX="[0-9]\+\.[0-9]\+\.[0-9]\+\(-\(\(rc\)\|\(snapshot\)\)\(\.\)\?[0-9]\+\)\?$"

get_remote () {
  local remote
  local org=${1:-cilium}
  local repo=${2:-cilium}
  remote=$(git remote -v | \
    grep "github.com[/:]${org}/${repo}" | \
    head -n1 | cut -f1)
  if [ -z "$remote" ]; then
      echo "No remote git@github.com:${org}/${repo}.git or https://github.com/${org}/${repo} found" 1>&2
      return 1
  fi
  echo "$remote"
}

get_user() {
  gh_username=$(hub api user --flat | awk '/.login/ {print $2}')
  if [ "$gh_username" = "" ]; then
    echo "Error: could not get user info from hub" 1>&2
    exit 1
  fi
  echo $gh_username
}

# $1 - override
get_user_remote() {
  USER_REMOTE=${1:-}
  if [ "$USER_REMOTE" = "" ]; then
      gh_username=$(get_user)
      USER_REMOTE=$(get_remote "$gh_username")
      echo "Using GitHub repository ${gh_username}/cilium (git remote: ${USER_REMOTE})" 1>&2
  fi
  echo $USER_REMOTE
}

is_collaborator() {
  local username=${1:-}
  local org=${2:-cilium}
  local repo=${3:-cilium}
  if [ -z "$username" ]; then
      echo "Error: no username specified in is_collaborator"
      exit 1
  fi
  local path="repos/$org/$repo/collaborators/$username"
  if hub api "$path" &> /dev/null; then
    echo "yes"
  else
    echo "no"
  fi
}

require_linux() {
  if [ "$(uname)" != "Linux" ]; then
      echo "$0: Linux required"
      exit 1
  fi
}

commit_in_upstream() {
    local commit="$1"
    local branch="$2"
    local org="${3:-"cilium"}"
    local repo="${4:-"cilium"}"
    local remote="$(get_remote ${org} ${repo})"
    local branches="$(git branch -q -r --contains $commit $remote/$branch 2> /dev/null)"
    echo "$branches" | grep -q ".*$remote/$branch"
}

get_branch_from_version() {
    local remote="$1"
    local branch="$(echo $2 | sed 's/.*\(v[0-9]\+\.[0-9]\+\).*/\1/')"
    if [ -z "$(git ls-remote --heads $remote $branch)" ]; then
        branch="main"
    fi
    echo "$branch"
}
