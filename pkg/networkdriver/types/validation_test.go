// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateInterfaceNameLength tests the 15-character length limit
func TestValidateInterfaceNameLength(t *testing.T) {
	tests := []struct {
		name      string
		ifName    string
		shouldErr bool
	}{
		{
			name:      "empty name is valid",
			ifName:    "",
			shouldErr: false,
		},
		{
			name:      "1 char name",
			ifName:    "a",
			shouldErr: false,
		},
		{
			name:      "exactly 15 chars (max)",
			ifName:    "abcdefghijklmno",
			shouldErr: false,
		},
		{
			name:      "16 chars (too long)",
			ifName:    "abcdefghijklmnop",
			shouldErr: true,
		},
		{
			name:      "way too long",
			ifName:    "this-interface-name-is-way-too-long",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.ifName)
			if tt.shouldErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "too long")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateInterfaceNameCharacters tests character validation
func TestValidateInterfaceNameCharacters(t *testing.T) {
	tests := []struct {
		name      string
		ifName    string
		shouldErr bool
	}{
		// Valid characters
		{
			name:      "alphanumeric",
			ifName:    "eth0",
			shouldErr: false,
		},
		{
			name:      "with dash",
			ifName:    "my-net-0",
			shouldErr: false,
		},
		{
			name:      "with underscore",
			ifName:    "my_net_0",
			shouldErr: false,
		},
		{
			name:      "with dot",
			ifName:    "my.net.0",
			shouldErr: false,
		},
		{
			name:      "mixed valid chars",
			ifName:    "a1-b2_c3.d4",
			shouldErr: false,
		},
		// Invalid characters
		{
			name:      "with colon",
			ifName:    "eth:0",
			shouldErr: true,
		},
		{
			name:      "with slash",
			ifName:    "eth/0",
			shouldErr: true,
		},
		{
			name:      "with space",
			ifName:    "my net",
			shouldErr: true,
		},
		{
			name:      "with tab",
			ifName:    "my\tnet",
			shouldErr: true,
		},
		{
			name:      "with special char",
			ifName:    "eth@0",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.ifName)
			if tt.shouldErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid characters")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateInterfaceNameReserved tests reserved name detection
func TestValidateInterfaceNameReserved(t *testing.T) {
	tests := []struct {
		name      string
		ifName    string
		shouldErr bool
	}{
		{
			name:      "loopback",
			ifName:    "lo",
			shouldErr: true,
		},
		{
			name:      "cilium_host",
			ifName:    "cilium_host",
			shouldErr: true,
		},
		{
			name:      "cilium_net",
			ifName:    "cilium_net",
			shouldErr: true,
		},
		{
			name:      "cilium without underscore is ok",
			ifName:    "ciliumnet",
			shouldErr: false,
		},
		{
			name:      "normal eth",
			ifName:    "eth0",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.ifName)
			if tt.shouldErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "reserved")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateInterfaceNameRealWorld tests real-world interface names
func TestValidateInterfaceNameRealWorld(t *testing.T) {
	validNames := []string{
		"eth0", "eth1", "net0", "net1",
		"mynet0", "app-net", "app_net",
		"sriov0", "dpdk0", "vf0",
		"veth0", "macvlan0", "bond0",
		"enp1s0f0", // SR-IOV style
		"eth0.100", // VLAN
	}

	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			err := ValidateInterfaceName(name)
			assert.NoError(t, err, "Valid name %q should pass validation", name)
		})
	}

	invalidNames := map[string]string{
		"eth:0":                       "colon",
		"eth 0":                       "space",
		"verylonginterfacename":       "too long",
		"lo":                          "reserved",
		"cilium_host":                 "reserved",
		"eth0\n":                      "newline",
		"interface-name-way-too-long": "too long",
	}

	for name, reason := range invalidNames {
		t.Run(name+"_"+reason, func(t *testing.T) {
			err := ValidateInterfaceName(name)
			assert.Error(t, err, "Invalid name %q should fail validation (reason: %s)", name, reason)
		})
	}
}

// TestDeviceConfigEmpty tests Empty() method considers PodIfName
func TestDeviceConfigEmpty(t *testing.T) {
	tests := []struct {
		name     string
		config   DeviceConfig
		expected bool
	}{
		{
			name:     "completely empty",
			config:   DeviceConfig{},
			expected: true,
		},
		{
			name: "only podIfName set",
			config: DeviceConfig{
				PodIfName: "eth1",
			},
			expected: false,
		},
		{
			name: "all fields set",
			config: DeviceConfig{
				PodIfName: "custom-if",
				Vlan:      100,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.Empty()
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestValidateInterfaceNameEdgeCases tests edge cases
func TestValidateInterfaceNameEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		ifName    string
		shouldErr bool
	}{
		{
			name:      "just numbers",
			ifName:    "123",
			shouldErr: false,
		},
		{
			name:      "starts with number",
			ifName:    "0eth",
			shouldErr: false,
		},
		{
			name:      "starts with dash",
			ifName:    "-eth0",
			shouldErr: false,
		},
		{
			name:      "exactly 15 valid chars",
			ifName:    "123456789012345",
			shouldErr: false,
		},
		{
			name:      "unicode not allowed",
			ifName:    "ethñ",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateInterfaceName(tt.ifName)
			if tt.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
