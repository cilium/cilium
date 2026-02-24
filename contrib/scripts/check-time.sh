#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

GOIMPORTS=("golang.org/x/tools/cmd/goimports" "-w")
MATCH="^[^a-zA-Z]*\"time\"$"
EXCLUDED_DIRS=(
  # Wrapper directories
  "time"

  # Generated directories
  "api"
  "client"
  "slim"

  # Not Go source
  ".git"
  "_build"
  "contrib"
  "externalversions"
  "examples"
  "install"
  "Documentation"

  # Not for cilium-agent
  "bugtool"
  "cilium-dbg"
  "clustermesh"
  "clustermesh-apiserver"
  "health"
  "operator"
  "plugins"
  "tools"
  "test"
  "testutils"
  "vendor"

  # Not for cilium-cli
  "cilium-cli"

  # Source shared with other binaries
  "hive"
  "lock"

  # Skip override (not applicable)
  "defaults"
  "loadinfo"
  "logging"
  "metric"
  "probes"
  "rand"
  "types"

  # May need subsequent evaluation to detect resiliency issues in CI
  "rate"
  "resiliency"
)

find_match() {
  local target="."

  # shellcheck disable=2046
  grep "$@" -r --include \*.go \
       $(printf "%s\n" "${EXCLUDED_DIRS[@]}" \
         | xargs -I{} echo '--exclude-dir={}') \
       --exclude \*_test.go \
       -i "$MATCH" \
       "$target"
}

check() {
  # Used to cause failure when pkg/time is not used
  if find_match ; then
    >&2 echo "Found match for '$MATCH'. Please use pkg/time instead to improve ordering and consistency testing.";
    >&2 echo "Run '$0 update' to update most instances automatically."
    exit 1
  fi
}

update() {
  local files=()

  while IFS='' read -r line; do
    files+=("$line");
  done < <(find_match -l | sort -u)
  if [ "${#files[@]}" -eq 0 ]; then
      return
  fi

  # Add a cilium pkg/time input next to the other imports
  sed -i '/'"$MATCH"'/d; /"github.com\/cilium\/cilium\/.*"/a\
	"github.com/cilium/cilium/pkg/time"' \
      "${files[@]}"

  # Fix up imports formatting
  printf "%s\n" "${files[@]}" \
  | xargs dirname \
  | sort -u \
  | xargs go run "${GOIMPORTS[@]}"
}

main() {
  if [ $# -ge 1 ] && [ "$1" == "update" ]; then
      update
  fi

  check
}

main "$@"
