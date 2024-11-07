// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

// This file duplicates the stubs that exist in vishvananda/netlink outside the linux build. Not all
// functions defined in found in netlink_linux.go are present here, because not all have a stub in
// vishvananda/netlink, and thus some of the necessary function signature types are missing outside
// the linux build.

package safenetlink

import (
	"net"

	"github.com/vishvananda/netlink"
)

func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return nil, netlink.ErrNotImplemented
}

func ChainList(link netlink.Link, parent uint32) ([]netlink.Chain, error) {
	return nil, netlink.ErrNotImplemented
}

func ClassList(link netlink.Link, parent uint32) ([]netlink.Class, error) {
	return nil, netlink.ErrNotImplemented
}

func ConntrackTableList(table netlink.ConntrackTableType, family netlink.InetFamily) ([]*netlink.ConntrackFlow, error) {
	return nil, netlink.ErrNotImplemented
}

func FilterList(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
	return nil, netlink.ErrNotImplemented
}

func FouList(fam int) ([]netlink.Fou, error) {
	return nil, netlink.ErrNotImplemented
}

func GenlFamilyList() ([]*netlink.GenlFamily, error) {
	return nil, netlink.ErrNotImplemented
}

func LinkByName(name string) (netlink.Link, error) {
	return nil, netlink.ErrNotImplemented
}

func LinkByAlias(alias string) (netlink.Link, error) {
	return nil, netlink.ErrNotImplemented
}

func LinkList() ([]netlink.Link, error) {
	return nil, netlink.ErrNotImplemented
}

func NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return nil, netlink.ErrNotImplemented
}

func NeighProxyList(linkIndex, family int) ([]netlink.Neigh, error) {
	return nil, netlink.ErrNotImplemented
}

func LinkGetProtinfo(link netlink.Link) (netlink.Protinfo, error) {
	return netlink.Protinfo{}, netlink.ErrNotImplemented
}

func QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	return nil, netlink.ErrNotImplemented
}

func RdmaLinkDel(name string) error {
	return netlink.ErrNotImplemented
}

func RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return nil, netlink.ErrNotImplemented
}

func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return nil, netlink.ErrNotImplemented
}

func RouteListFilteredIter(family int, filter *netlink.Route, filterMask uint64, f func(netlink.Route) (cont bool)) error {
	return netlink.ErrNotImplemented
}

func RuleList(family int) ([]netlink.Rule, error) {
	return nil, netlink.ErrNotImplemented
}

func RuleListFiltered(family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketGet(local, remote net.Addr) (*netlink.Socket, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagTCPInfo(family uint8) ([]*netlink.InetDiagTCPInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagTCP(family uint8) ([]*netlink.Socket, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagUDPInfo(family uint8) ([]*netlink.InetDiagUDPInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagUDP(family uint8) ([]*netlink.Socket, error) {
	return nil, netlink.ErrNotImplemented
}

func UnixSocketDiagInfo() ([]*netlink.UnixDiagInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func UnixSocketDiag() ([]*netlink.UnixSocket, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketXDPGetInfo(ino uint32, cookie uint64) (*netlink.XDPDiagInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagXDP() ([]*netlink.XDPDiagInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func XfrmPolicyList(family int) ([]netlink.XfrmPolicy, error) {
	return nil, netlink.ErrNotImplemented
}

func XfrmStateList(family int) ([]netlink.XfrmState, error) {
	return nil, netlink.ErrNotImplemented
}
