// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safenetlink

// HandleConfig configures the behavior of NewHandle
type HandleConfig struct {
	// EnableVFInfo toggles collection of VF (Virtual Function) information during
	// link list operations. Disabled by default.
	EnableVFInfo bool

	// NLFamilies specifies the netlink protocol families to use when creating the handle.
	// If empty, defaults to NETLINK_ROUTE, NETLINK_XFRM, NETLINK_NETFILTER.
	NLFamilies []int
}
