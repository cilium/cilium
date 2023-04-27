// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"
)

func TestCoalesceCIDRs(t *testing.T) {
	CIDR := []string{"10.0.0.0/8"}
	expectedCIDR := []string{"10.0.0.0/8"}
	newCIDR := coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"10.105.0.0/16", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"10.105.0.0/16", "10.104.0.0/19", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	expectedCIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8", "f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96", "10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"f00d::a0f:0:0:0/96"}
	newCIDR = coalesceCIDRs(CIDR)
	if len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v\n", newCIDR, expectedCIDR)
	}
}
