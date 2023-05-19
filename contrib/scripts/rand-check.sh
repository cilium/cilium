#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

# Make sure pkg/rand is used instead of math/rand, see
# https://github.com/cilium/cilium/issues/10988. It's fine to use math/rand in
# tests though.
for l in rand\.NewSource; do
  m=$(find . -name "*.go" \
	  -not -name "*_test.go" \
	  -not -path "./.git/*" \
	  -not -path "./_build/*" \
	  -not -path "./contrib/*" \
	  -not -path "./pkg/rand/*" \
	  -not -regex ".*/vendor/.*" \
	  -not -path "./test/*" \
	  -print0 \
	  | xargs -0 grep --exclude NewSafeSource "$l")
  if [[ ! -z "$m" ]] ; then
    echo "Found $l usage. Please use pkg/rand instead for a concurrency-safe implementation:"
    echo $m
    exit 1
  fi
done
