// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ethtool

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestIsVirtualDriver(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		name := "veth0"
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: name},
			PeerName:  "veth1",
		}
		err := netlink.LinkAdd(veth)
		if err != nil {
			t.Fatalf("failed to create veth link: %v", err)
		}
		defer netlink.LinkDel(veth)

		isVirtual, err := IsVirtualDriver(name)
		if err != nil {
			t.Fatalf("error checking veth link %q: %v", name, err)
		} else if !isVirtual {
			t.Errorf("IsVirtualDriver(%q) = %t, want true", name, isVirtual)
		}
		return nil
	})
}
