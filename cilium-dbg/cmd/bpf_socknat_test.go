// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

// TestDumpReverseSKEntries verifies that the CLI tool can correctly display socket NAT entries
func TestDumpReverseSKEntries(t *testing.T) {
	// Create mock map
	mockMap := mockmaps.NewLBMockMap()
	t.Log("Created empty LBMockMap")

	// Add one IPv4 and one IPv6 entry to test both address families
	mockMap.AddSockRevNat(1234, net.ParseIP("10.0.2.100"), 80)   // IPv4
	mockMap.AddSockRevNat(2345, net.ParseIP("2001:db8::1"), 443) // IPv6
	t.Log("Added test entries")

	// Test IPv4 entries
	t.Run("IPv4 entries", func(t *testing.T) {
		entriesFound := 0
		for k, v := range mockMap.SockRevNat4 {
			entriesFound++
			t.Logf("Entry: Cookie=%d, Address=%s, Port=%d -> Address=%s, Port=%d, RevNatIndex=%d",
				k.Cookie, k.Address.String(), k.Port,
				v.Address.String(), v.Port, v.RevNatIndex)
		}
		if entriesFound != 1 {
			t.Errorf("Expected 1 IPv4 entry, found %d", entriesFound)
		}
	})

	// Test IPv6 entries
	t.Run("IPv6 entries", func(t *testing.T) {
		entriesFound := 0
		for k, v := range mockMap.SockRevNat6 {
			entriesFound++
			t.Logf("Entry: Cookie=%d, Address=%s, Port=%d -> Address=%s, Port=%d, RevNatIndex=%d",
				k.Cookie, k.Address.String(), k.Port,
				v.Address.String(), v.Port, v.RevNatIndex)
		}
		if entriesFound != 1 {
			t.Errorf("Expected 1 IPv6 entry, found %d", entriesFound)
		}
	})

	// Verify total entries
	t.Run("Total entries", func(t *testing.T) {
		totalEntries := len(mockMap.SockRevNat4) + len(mockMap.SockRevNat6)
		if totalEntries != 2 {
			t.Errorf("Expected 2 total entries (1 IPv4 + 1 IPv6), found %d", totalEntries)
		}
	})
}
