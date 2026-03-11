// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package inl

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/inl"
	"github.com/cilium/cilium/pkg/netns"
)

// NetNSHandle returns a [netlink.Handle] created in the given network
// namespace.
func NetNSHandle(tb testing.TB, ns *netns.NetNS) *netlink.Handle {
	tb.Helper()

	var h *netlink.Handle

	f := func() error {
		var err error
		h, err = inl.NewHandle(nil)
		if err != nil {
			return err
		}
		return nil
	}

	if ns != nil {
		if err := ns.Do(f); err != nil {
			tb.Fatalf("creating namespaced netlink handle: %v", err)
		}
	} else {
		if err := f(); err != nil {
			tb.Fatalf("creating netlink handle: %v", err)
		}
	}

	tb.Cleanup(func() {
		if err := h.Close(); err != nil {
			tb.Fatalf("closing netlink handle: %v", err)
		}
	})

	return h
}
