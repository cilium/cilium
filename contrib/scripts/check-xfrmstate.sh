#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

GOIMPORTS=("golang.org/x/tools/cmd/goimports" "-w")
MATCHES=(
    "netlink.XfrmStateAdd"
    "netlink.XfrmStateUpdate"
    "netlink.XfrmStateDel"
    "netlink.XfrmStateFlush"
)

find_match() {
  local target="./pkg/datapath"

  MATCHES_ORED=$(printf "|%s" "${MATCHES[@]}")
  MATCHES_ORED=${MATCHES_ORED:1}

  grep -lr --include \*.go \
       --exclude \*_test.go \
       --exclude xfrm_state_cache.go \
       --exclude probe_linux.go \
       -E "$MATCHES_ORED" \
        "$target"
  if [ $? -eq 0 ] ; then
    return 0
  fi

  # Let's check now that we can detect it correctly
  NO_MATCHES=$(grep -or --include xfrm_state_cache.go \
       -E "$MATCHES_ORED" \
       "$target" | wc -l)

  if [ "$NO_MATCHES" -eq "4" ] ; then
    return 1
  fi
  # Incorrect number of matches
  echo "Found incorrect number of matches: $NO_MATCHES"
  return 0
}

check() {
  if find_match ; then
    # shellcheck disable=SC2145
    >&2 echo "Found match for '${MATCHES[@]}'. Please use xfrmStateCache instead.";
    exit 1
  fi
}

main() {
  check
}

main "$@"
