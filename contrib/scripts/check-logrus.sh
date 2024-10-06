#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

GOIMPORTS=("golang.org/x/tools/cmd/goimports" "-w")
MATCH="^\s*\"github.com/sirupsen/logrus\"$"

# File paths that have switched to slog and for which reintroducing use of logrus
# is forbidden.
CONVERTED=(
  "hubble"
  "pkg/hive/health"
  "pkg/datapath/linux"
  "operator/pkg/ciliumenvoyconfig"
  "operator/pkg/controller-runtime"
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
