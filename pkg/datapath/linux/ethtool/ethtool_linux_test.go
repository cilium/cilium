// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ethtool

import (
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestIsVirtualDriver(t *testing.T) {
	testutils.PrivilegedTest(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	oldns, err := netns.Get()
	if err != nil {
		t.Fatalf("failed to get current netns: %v", err)
	}
	defer oldns.Close()

	newns, err := netns.New()
	if err != nil {
		t.Fatalf("failed to create new netns: %v", err)
	}
	defer newns.Close()
	defer netns.Set(oldns)

	name := "veth0"
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(veth)
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
}
