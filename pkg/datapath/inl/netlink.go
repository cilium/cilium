// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package inl

import (
	"github.com/vishvananda/netlink"
)

// HandleConfig configures the behavior of [NewHandle].
type HandleConfig struct {
	// EnableVFInfo toggles collection of VF (Virtual Function) information during
	// link list operations. Disabled by default.
	EnableVFInfo bool

	// NLFamilies specifies the netlink protocol families to use when creating the
	// handle. If empty, defaults to NETLINK_ROUTE, NETLINK_XFRM,
	// NETLINK_NETFILTER.
	NLFamilies []int
}

// NewHandle returns a [netlink.Handle] based on a [HandleConfig].
func NewHandle(cfg *HandleConfig) (*netlink.Handle, error) {
	if cfg == nil {
		cfg = &HandleConfig{}
	}

	//nolint:forbidigo
	handle, err := netlink.NewHandle(cfg.NLFamilies...)
	if err != nil {
		return nil, err
	}

	if !cfg.EnableVFInfo {
		handle.DisableVFInfoCollection()
	}

	return handle, nil
}
