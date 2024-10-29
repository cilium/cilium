#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

set -eu

# List based on https://github.com/vishvananda/netlink/pull/1018
MATCHES=(
    "netlink.AddrList"
    "netlink.BridgeVlanList"
    "netlink.ChainList"
    "netlink.ClassList"
    "netlink.ConntrackTableList"
    "netlink.DevLinkGetDeviceList"
    "netlink.DevLinkGetAllPortList"
    "netlink.DevlinkGetDeviceParams"
    "netlink.FilterList"
    "netlink.FouList"
    "netlink.GenlFamilyList"
    "netlink.GTPPDPList"
    "netlink.LinkByName"
    "netlink.LinkByAlias"
    "netlink.LinkList"
    "netlink.LinkSubscribeWithOptions"
    "netlink.NeighList"
    "netlink.NeighProxyList"
    "netlink.NeighListExecute"
    "netlink.LinkGetProtinfo"
    "netlink.QdiscList"
    "netlink.RdmaLinkList"
    "netlink.RdmaLinkByName"
    "netlink.RdmaLinkDel"
    "netlink.RouteList"
    "netlink.RouteListFiltered"
    "netlink.RouteListFilteredIter"
    "netlink.RouteSubscribeWithOptions"
    "netlink.RuleList"
    "netlink.RuleListFiltered"
    "netlink.SocketGet"
    "netlink.SocketDiagTCPInfo"
    "netlink.SocketDiagTCP"
    "netlink.SocketDiagUDPInfo"
    "netlink.SocketDiagUDP"
    "netlink.UnixSocketDiagInfo"
    "netlink.UnixSocketDiag"
    "netlink.SocketXDPGetInfo"
    "netlink.SocketDiagXDP"
    "netlink.VDPAGetDevList"
    "netlink.VDPAGetDevConfigList"
    "netlink.VDPAGetMGMTDevList"
    "netlink.XfrmPolicyList"
    "netlink.XfrmStateList"
)

EXCLUDED_DIRS=(
  ".git"
  "_build"
  "contrib"
  "Documentation"
  "externalversions"
  "examples"
  "install"
  "test"
  "vendor"

  "safenetlink"
)

find_match() {
  local target="."

  MATCHES_ORED=$(printf '|\W%s\(' "${MATCHES[@]}")
  MATCHES_ORED=${MATCHES_ORED:1}

  # shellcheck disable=2046
  grep "$@" -r --include \*.go \
       $(printf "%s\n" "${EXCLUDED_DIRS[@]}" \
         | xargs -I{} echo '--exclude-dir={}') \
       --exclude \*_test.go \
       -E "$MATCHES_ORED" \
       "$target"
  return $?
}


check() {
  if find_match ; then
    >&2 echo "Found unprotected netlink call(s) that can may fail with netlink.ErrDumpInterrupted. Please use the safenetlink package for these function calls instead.";
    exit 1
  fi
}

main() {
  check
}

main "$@"
