// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ethtool

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestIsVirtualDriver(t *testing.T) {
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("failed to get link list: %v", err)
	}

	for _, link := range links {
		name := link.Attrs().Name
		isVirtual, err := IsVirtualDriver(name)
		if errors.Is(err, unix.EOPNOTSUPP) {
			continue
		} else if err != nil {
			t.Fatalf("failed to check for veth driver for %q: %v", name, err)
		}
		t.Logf("IsVirtualDriver(%q) = %t", name, isVirtual)
	}
}
