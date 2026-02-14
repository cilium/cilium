#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -euo pipefail

# Gating test code behind arbitrary tags is problematic as it makes whole files
# invisible from gopls unless extra configuration is added.
#
# When refactoring, this often leads to 'late' failures in CI that could've been
# caught locally, wasting CI and dev time and resources. All code should be
# buildable using a simple `go test ./...`.
#
# If some tests need to be skipped or only executed in certain scenarios, use
# test helpers and runtime checks instead of build tags. See the testutils
# package for examples. Do NOT extend this list without some form of consensus
# among committers.
allowed="linux|windows|darwin|race"

script=$(cat << 'EOF'
  /^\/\/go:build / {
    for (i = 2; i <= NF; i++) {
      tag = $i
      gsub(/[^a-zA-Z0-9_]/, "", tag)

      if (tag != "" && tag !~ allowed) {
        printf "%s uses forbidden tag \"%s\"\n", FILENAME, tag
        status = 1
      }
    }
  }
  !/^\/\// && !/^$/ { nextfile }
  END { if (status) exit 1 }
EOF
)

find . -name "*_test.go" -print0 | xargs -0 awk -v allowed="^($allowed)$" "$script"
