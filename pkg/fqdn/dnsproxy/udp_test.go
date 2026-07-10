// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"net"
	"testing"
)

func TestComputeIPv6Checksum(t *testing.T) {
	testCases := []struct {
		name        string
		srcIP       net.IP
		dstIP       net.IP
		udpPayload  []byte
		expectedSum uint16
	}{
		{
			name:  "Transmitted Checksum for Even Number of Words",
			srcIP: net.IPv6loopback,
			dstIP: net.IPv6loopback,
			udpPayload: []byte{
				0x01, 0x02, // Sample data (16-bit word 1)
				0x03, 0x04, // Sample data (16-bit word 2)
			},
			expectedSum: 0xfbe2,
		},
		{
			name:  "Transmitted Checksum for Odd Number of Words",
			srcIP: net.IPv6loopback,
			dstIP: net.IPv6loopback,
			udpPayload: []byte{
				0x01, 0x02, // Sample data (16-bit word 1)
				0x03, 0x04, // Sample data (16-bit word 2)
				0x05, 0x06, // Sample data (16-bit word 3)
			},
			expectedSum: 0xf6da,
		},
		{
			name:        "No Transmitted Checksum",
			srcIP:       net.IPv6unspecified,
			dstIP:       net.IPv6unspecified,
			udpPayload:  nil,
			expectedSum: 0xffff, // Transmit all ones if the computed checksum is zero
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checksum := computeIPv6Checksum(tc.srcIP, tc.dstIP, tc.udpPayload)
			if checksum != tc.expectedSum {
				t.Errorf("Expected checksum %04X, but got %04X", tc.expectedSum, checksum)
			}
		})
	}
}
