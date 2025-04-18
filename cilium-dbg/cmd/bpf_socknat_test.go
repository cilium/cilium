// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	"github.com/cilium/cilium/pkg/types"
)

func TestDumpReverseSKEntries(t *testing.T) {
	// Initialize maps
	lbmap.Init(lbmap.InitParams{IPv4: true, IPv6: true})

	// Create mock LB map
	mockMap := mockmaps.NewLBMockMap()

	// Store original maps and restore after test
	originalMap4 := lbmap.RevNat4Map
	originalMap6 := lbmap.RevNat6Map
	defer func() {
		lbmap.RevNat4Map = originalMap4
		lbmap.RevNat6Map = originalMap6
	}()

	// Test IPv4 entries
	key1 := lbmap.SockRevNat4Key{
		Cookie:  12345,
		Address: types.IPv4{10, 0, 2, 15},
		Port:    8080,
	}
	value1 := lbmap.SockRevNat4Value{
		RevNatIndex: 42,
		Address:     types.IPv4{192, 168, 1, 1},
		Port:        80,
	}
	mockMap.SockRevNat4[key1] = value1

	// Test IPv6 entries
	key2 := lbmap.SockRevNat6Key{
		Cookie: 12346,
		Address: types.IPv6{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
			0, 1},
		Port: 8080,
	}
	value2 := lbmap.SockRevNat6Value{
		RevNatIndex: 43,
		Address: types.IPv6{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
			0, 2},
		Port: 80,
	}
	mockMap.SockRevNat6[key2] = value2

	// Create entries map for testing
	entries := make(map[string][]string)

	// Call the function being tested
	dumpReverseSKEntries(entries)

	// Verify IPv4 contents
	require.Contains(t, entries, "12345")
	entry4 := entries["12345"]
	require.Len(t, entry4, 1)
	require.Contains(t, entry4[0], "10.0.2.15:8080")
	require.Contains(t, entry4[0], "192.168.1.1:80")
	require.Contains(t, entry4[0], "(revnat=42)")

	// Verify IPv6 contents
	require.Contains(t, entries, "12346")
	entry6 := entries["12346"]
	require.Len(t, entry6, 1)
	require.Contains(t, entry6[0], "[fd00::1]:8080")
	require.Contains(t, entry6[0], "[fd00::2]:80")
	require.Contains(t, entry6[0], "(revnat=43)")
}