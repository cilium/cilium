#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

MATCH="^\s*\"github.com/sirupsen/logrus\"$"

# File paths that have switched to slog and for which reintroducing use of logrus
# is forbidden.
CONVERTED=(
  "api/v1"
  "hubble"
  "pkg/auth"
  "pkg/hive/health"
  "pkg/datapath/linux"
  "operator/api"
  "operator/auth"
  "operator/doublewrite"
  "operator/endpointgc"
  "operator/identitygc"
  "operator/metrics"
  "operator/pkg"
  "operator/watchers"
)

EXCLUDED_FILES=(
  # pkg/datapath/linux/...
  "routing.go"
)

for dir in "${CONVERTED[@]}"; do
  if grep -r --include \*.go -i "$MATCH" --exclude-from=<(printf "%s\n" "${EXCLUDED_FILES[@]}") "$dir"; then
      >&2 echo "Found match for '$MATCH'. Please use slog and not logrus."
      >&2 echo "slog is available via Hive with type *slog.Logger"
      exit 1
  fi
done
