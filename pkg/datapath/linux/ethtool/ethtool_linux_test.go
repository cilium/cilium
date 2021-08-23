// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package ethtool

import (
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
		if err == unix.EOPNOTSUPP {
			continue
		} else if err != nil {
			t.Fatalf("failed to check for veth driver for %q: %v", name, err)
		}
		t.Logf("IsVirtualDriver(%q) = %t", name, isVirtual)
	}
}
