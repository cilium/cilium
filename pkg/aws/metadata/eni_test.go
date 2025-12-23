// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAWSPattern(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		expectAWS   bool
		expectIndex int
	}{
		{
			name:        "aws0 pattern",
			pattern:     "aws0",
			expectAWS:   true,
			expectIndex: 0,
		},
		{
			name:        "aws1 pattern",
			pattern:     "aws1",
			expectAWS:   true,
			expectIndex: 1,
		},
		{
			name:        "aws+ pattern (all AWS interfaces)",
			pattern:     "aws+",
			expectAWS:   true,
			expectIndex: -1,
		},
		{
			name:        "aws pattern (all AWS interfaces)",
			pattern:     "aws",
			expectAWS:   true,
			expectIndex: -1,
		},
		{
			name:        "eth0 pattern (not AWS)",
			pattern:     "eth0",
			expectAWS:   false,
			expectIndex: -1,
		},
		{
			name:        "ens+ pattern (not AWS)",
			pattern:     "ens+",
			expectAWS:   false,
			expectIndex: -1,
		},
		{
			name:        "aws10 pattern",
			pattern:     "aws10",
			expectAWS:   true,
			expectIndex: 10,
		},
		{
			name:        "awsxyz pattern (invalid)",
			pattern:     "awsxyz",
			expectAWS:   false,
			expectIndex: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAWS, deviceIndex := IsAWSPattern(tt.pattern)
			assert.Equal(t, tt.expectAWS, isAWS, "IsAWSPattern mismatch for %s", tt.pattern)
			assert.Equal(t, tt.expectIndex, deviceIndex, "Device index mismatch for %s", tt.pattern)
		})
	}
}

func TestENIInterface(t *testing.T) {
	eni := ENIInterface{
		InterfaceID: "eni-0123456789abcdef0",
		DeviceIndex: 0,
		PrivateIP:   "10.0.1.10",
		MACAddress:  "06:11:22:33:44:55",
		IfName:      "ens5",
	}

	assert.Equal(t, "eni-0123456789abcdef0", eni.InterfaceID)
	assert.Equal(t, 0, eni.DeviceIndex)
	assert.Equal(t, "10.0.1.10", eni.PrivateIP)
	assert.Equal(t, "06:11:22:33:44:55", eni.MACAddress)
	assert.Equal(t, "ens5", eni.IfName)
}

func TestMarshalENIList(t *testing.T) {
	enis := []ENIInterface{
		{
			InterfaceID: "eni-0123456789abcdef0",
			DeviceIndex: 0,
			PrivateIP:   "10.0.1.10",
			MACAddress:  "06:11:22:33:44:55",
			IfName:      "ens5",
		},
		{
			InterfaceID: "eni-0fedcba9876543210",
			DeviceIndex: 1,
			PrivateIP:   "10.0.2.10",
			MACAddress:  "06:11:22:33:44:66",
			IfName:      "ens6",
		},
	}

	jsonStr := MarshalENIList(enis)
	assert.Contains(t, jsonStr, "eni-0123456789abcdef0")
	assert.Contains(t, jsonStr, "ens5")
	assert.Contains(t, jsonStr, "eni-0fedcba9876543210")
	assert.Contains(t, jsonStr, "ens6")
}

// mockENILister is a mock implementation of ENILinkLister for testing
type mockENILister struct {
	interfaces map[string]string // MAC -> interface name
}

func (m *mockENILister) GetInterfaceNameByMAC(mac string) (string, error) {
	if name, ok := m.interfaces[mac]; ok {
		return name, nil
	}
	return "", nil
}

func TestResolvePatterns(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()
	eniLister := &mockENILister{
		interfaces: map[string]string{
			"06:11:22:33:44:55": "ens5",
		},
	}

	tests := []struct {
		name     string
		patterns []string
		// We can't test actual resolution without IMDS, but we can test
		// that non-AWS patterns pass through unchanged
	}{
		{
			name:     "non-AWS patterns pass through",
			patterns: []string{"eth0", "eth1", "ens+"},
		},
		{
			name:     "mixed patterns",
			patterns: []string{"eth0", "aws0", "ens+"},
		},
		{
			name:     "empty list",
			patterns: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This will fail to resolve AWS patterns (no IMDS in test env)
			// but should preserve non-AWS patterns
			result := ResolvePatterns(ctx, logger, tt.patterns, eniLister)

			// Count non-AWS patterns in input
			nonAWS := 0
			for _, p := range tt.patterns {
				if isAWS, _ := IsAWSPattern(p); !isAWS {
					nonAWS++
				}
			}

			// All non-AWS patterns should be preserved
			// (AWS patterns will be kept as-is due to IMDS failure)
			assert.GreaterOrEqual(t, len(result), nonAWS,
				"Should preserve at least non-AWS patterns")
		})
	}
}
