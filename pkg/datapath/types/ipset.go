// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "net/netip"

const (
	CiliumNodeIPSetV4 = "cilium_node_set_v4"
	CiliumNodeIPSetV6 = "cilium_node_set_v6"
)

// IPSetFamily represents the protocol family of the IP addresses to be stored in the set.
type IPSetFamily string

const (
	INetFamily  IPSetFamily = "inet"
	INet6Family IPSetFamily = "inet6"
)

// IPSetManager provides management of kernel IpSets referenced by iptables rules.
type IPSetManager interface {
	// AddToIPSet adds the addresses to the ipset with given name and family.
	AddToIPSet(name string, family IPSetFamily, addrs ...netip.Addr)

	// RemoveFromBodeIPSet removes the addresses from the specified ipset.
	RemoveFromIPSet(name string, addrs ...netip.Addr)
}
