// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	vnl "github.com/vishvananda/netlink"
)

type netlink interface {
	LinkByName(name string) (vnl.Link, error)
	LinkSetARPOff(link vnl.Link) error
	LinkSetMTU(link vnl.Link, mtu int) error
	LinkAdd(link vnl.Link) error
	LinkSetUp(link vnl.Link) error
	AddrReplace(link vnl.Link, addr *vnl.Addr) error
	LinkDel(link vnl.Link) error
	LinkSetName(link vnl.Link, name string) error
	QdiscList(link vnl.Link) ([]vnl.Qdisc, error)
	QdiscDel(qdisc vnl.Qdisc) error
}

func newRealNetlink() netlink {
	return &vnl.Handle{}
}
