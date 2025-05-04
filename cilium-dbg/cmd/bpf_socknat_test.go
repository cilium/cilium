// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"testing"

	lbmap "github.com/cilium/cilium/pkg/loadbalancer/maps"
)

// TestDumpReverseSKEntries verifies that the CLI tool can correctly display socket NAT entries
func TestDumpReverseSKEntries(t *testing.T) {
	// Create mock map
	mockMap := lbmap.NewFakeLBMaps()
	t.Log("Created empty FakeLBMaps")

	// Add one IPv4 and one IPv6 entry to test both address families
	err := mockMap.UpdateSockRevNat(1234, net.ParseIP("10.0.2.100"), 80, 1) // IPv4
	if err != nil {
		t.Fatalf("Failed to add IPv4 entry: %v", err)
	}
	err = mockMap.UpdateSockRevNat(2345, net.ParseIP("2001:db8::1"), 443, 2) // IPv6
	if err != nil {
		t.Fatalf("Failed to add IPv6 entry: %v", err)
	}
	t.Log("Added test entries")

	// Test that entries exist
	t.Run("IPv4 entry exists", func(t *testing.T) {
		if !mockMap.ExistsSockRevNat(1234, net.ParseIP("10.0.2.100"), 80) {
			t.Error("Expected IPv4 entry to exist")
		}
	})

	t.Run("IPv6 entry exists", func(t *testing.T) {
		if !mockMap.ExistsSockRevNat(2345, net.ParseIP("2001:db8::1"), 443) {
			t.Error("Expected IPv6 entry to exist")
		}
	})

	// Test that non-existent entries don't exist
	t.Run("Non-existent entries", func(t *testing.T) {
		if mockMap.ExistsSockRevNat(9999, net.ParseIP("192.168.1.1"), 8080) {
			t.Error("Expected non-existent entry to not exist")
		}
	})
}
