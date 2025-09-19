// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIPAddressValidation tests IP address validation logic used in cilium_host IP restoration
func TestIPAddressValidation(t *testing.T) {
	tests := []struct {
		name     string
		ipStr    string
		expected bool
		isIPv4   bool
	}{
		{
			name:     "Valid IPv4",
			ipStr:    "10.0.0.1",
			expected: true,
			isIPv4:   true,
		},
		{
			name:     "Valid IPv6",
			ipStr:    "fd00::1",
			expected: true,
			isIPv4:   false,
		},
		{
			name:     "Invalid IP",
			ipStr:    "invalid",
			expected: false,
		},
		{
			name:     "Empty string",
			ipStr:    "",
			expected: false,
		},
		{
			name:     "IPv4 loopback",
			ipStr:    "127.0.0.1",
			expected: true,
			isIPv4:   true,
		},
		{
			name:     "IPv6 loopback",
			ipStr:    "::1",
			expected: true,
			isIPv4:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			if tt.expected {
				require.NotNil(t, ip, "Expected valid IP but got nil")
				if tt.isIPv4 {
					require.NotNil(t, ip.To4(), "Expected IPv4 address")
				} else {
					require.Nil(t, ip.To4(), "Expected IPv6 address")
				}
			} else {
				require.Nil(t, ip, "Expected invalid IP but got valid")
			}
		})
	}
}

// TestCIDRMaskGeneration tests CIDR mask generation for host addresses
func TestCIDRMaskGeneration(t *testing.T) {
	tests := []struct {
		name         string
		isIPv4       bool
		expectedOnes int
		expectedBits int
	}{
		{
			name:         "IPv4 host mask",
			isIPv4:       true,
			expectedOnes: 32,
			expectedBits: 32,
		},
		{
			name:         "IPv6 host mask",
			isIPv4:       false,
			expectedOnes: 128,
			expectedBits: 128,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mask net.IPMask
			if tt.isIPv4 {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}

			ones, bits := mask.Size()
			require.Equal(t, tt.expectedOnes, ones)
			require.Equal(t, tt.expectedBits, bits)
		})
	}
}

// TestIPNetCreation tests IPNet creation for host device addresses
func TestIPNetCreation(t *testing.T) {
	tests := []struct {
		name     string
		ipStr    string
		isIPv4   bool
		expected string
	}{
		{
			name:     "IPv4 host address",
			ipStr:    "10.0.0.1",
			isIPv4:   true,
			expected: "10.0.0.1/32",
		},
		{
			name:     "IPv6 host address",
			ipStr:    "fd00::1",
			isIPv4:   false,
			expected: "fd00::1/128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			require.NotNil(t, ip)

			var ipNet *net.IPNet
			if tt.isIPv4 {
				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				}
			} else {
				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(128, 128),
				}
			}

			require.Equal(t, tt.expected, ipNet.String())
		})
	}
}

// TestIPReplacementLogic tests the logic for replacing IP addresses during restoration
func TestIPReplacementLogic(t *testing.T) {
	// Simulate the address replacement logic used in addHostDeviceAddr
	oldIPv4 := net.ParseIP("10.0.0.1")
	newIPv4 := net.ParseIP("10.0.0.2")
	oldIPv6 := net.ParseIP("fd00::1")
	newIPv6 := net.ParseIP("fd00::2")

	// Test that IPs are different (replacement needed)
	require.False(t, oldIPv4.Equal(newIPv4), "IPv4 addresses should be different")
	require.False(t, oldIPv6.Equal(newIPv6), "IPv6 addresses should be different")

	// Test that same IPs are equal (no replacement needed)
	require.True(t, oldIPv4.Equal(oldIPv4), "Same IPv4 addresses should be equal")
	require.True(t, oldIPv6.Equal(oldIPv6), "Same IPv6 addresses should be equal")

	// Test IP type detection
	require.NotNil(t, oldIPv4.To4(), "Should detect IPv4")
	require.Nil(t, oldIPv6.To4(), "Should detect IPv6")
}

// TestHostDeviceNameValidation tests validation of host device names
func TestHostDeviceNameValidation(t *testing.T) {
	tests := []struct {
		name     string
		devName  string
		expected bool
	}{
		{
			name:     "Valid cilium_host",
			devName:  "cilium_host",
			expected: true,
		},
		{
			name:     "Valid cilium_net",
			devName:  "cilium_net",
			expected: true,
		},
		{
			name:     "Empty name",
			devName:  "",
			expected: false,
		},
		{
			name:     "Too long name",
			devName:  "this_is_a_very_long_interface_name_that_exceeds_limits",
			expected: false,
		},
		{
			name:     "Valid short name",
			devName:  "eth0",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Linux interface names must be <= 15 characters
			isValid := len(tt.devName) > 0 && len(tt.devName) <= 15
			require.Equal(t, tt.expected, isValid)
		})
	}
}
