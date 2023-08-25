#!/usr/bin/env bash

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

# This script provides two image tagging mechanisms.
#
# For general images that use most of the tree as input, it's most sensible to
# use git commit hash as a tag, or git version tag. Any tags that do not match
# a simple 2-dot version pattern are ignored, and commit hash is used.
#
# For images that use contents of a subdirectory as input, it's convenient to use
# a git tree hash. Running `git show` with tree hash based tag will display the
# contents of the subdirectory that was used as build input, mitigating any doubts
# in what was used to build this image.
#
# For both types of tags To differentiate any non-authoritative builds, i.e.
# builds from development branches, `-dev` suffix is added. Any builds that may
# include uncommitted changes will have `-wip` tag.

if [ "$#" -gt 1 ] ; then
  echo "$0 supports exactly 1 or no arguments"
  exit 1
fi

root_dir="$(git rev-parse --show-toplevel)"

cd "${root_dir}"

if [ "$#" -eq 1 ] ; then
  # if one argument was given, assume it's a directory and obtain a tree hash
  image_dir="${1}"
  if ! [ -d "${image_dir}" ] ; then
    echo "${image_dir} is not a directory (path is relative to git root)"
    exit 1
  fi
  git_ls_tree="$(git ls-tree --full-tree HEAD -- "${image_dir}")"
  if [ -z "${git_ls_tree}" ] ; then
    echo "${image_dir} exists, but it is not checked in git (path is relative to git root)"
    exit 1
  fi
  image_tag="$(printf "%s" "${git_ls_tree}" | sed 's/^[0-7]\{6\} tree \([0-9a-f]\{40\}\).*/\1/')"
else
  # if no arguments are given, attempt detecting if version tag is present,
  # otherwise use the a short commit hash
  image_dir="${root_dir}"
  git_tag="$(git name-rev --name-only --tags HEAD)"
  if printf "%s" "${git_tag}" | grep -q -E '^[v]?[0-9]+\.[0-9]+\.[0-9]+.*$' ; then
    # get tag in conventional format, since name-rev use the format with ^0 suffix,
    # however name-rev is required to determine presence of a tag
    git_tag="$(git tag --sort tag --points-at "${git_tag}")"
    # ensure version tag always has the v prefix and drop duplicates
    image_tag="$(printf "%s" "${git_tag}" | sed 's/^[v]*/v/' | uniq)"
  else
    # if no version tag is given, use commit hash
    image_tag="$(git rev-parse --short HEAD)"
    # only append -dev suffix when no version tag is used, since tags
    # can be set on release branches
    if [ -z "${WITHOUT_SUFFIX+x}" ] ; then
      if ! git merge-base --is-ancestor "$(git rev-parse HEAD)" origin/main ; then
        image_tag="${image_tag}-dev"
      fi
    fi
  fi
fi

if [ -z "${WITHOUT_SUFFIX+x}" ] ; then
  if [ "$(git status --porcelain "${image_dir}" | wc -l)" -gt 0 ] ; then
    image_tag="${image_tag}-wip"
  fi
fi

printf "%s" "${image_tag}"
