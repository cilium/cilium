// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package byteorder

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/cpu"
)

func TestHostToNetwork(t *testing.T) {
	if cpu.IsBigEndian {
		require.Equal(t, uint16(0xAABB), HostToNetwork16(0xAABB))
		require.Equal(t, uint32(0xAABBCCDD), HostToNetwork32(0xAABBCCDD))
	} else {
		require.Equal(t, uint16(0xBBAA), HostToNetwork16(0xAABB))
		require.Equal(t, uint32(0xDDCCBBAA), HostToNetwork32(0xAABBCCDD))
	}
}

func TestNetIPv4ToHost32(t *testing.T) {
	if cpu.IsBigEndian {
		require.Equal(t, uint32(0x0a0b815b), NetIPv4ToHost32(net.ParseIP("10.11.129.91")))
		require.Equal(t, uint32(0x0a0b8ad6), NetIPv4ToHost32(net.ParseIP("10.11.138.214")))
	} else {
		require.Equal(t, uint32(0x5b810b0a), NetIPv4ToHost32(net.ParseIP("10.11.129.91")))
		require.Equal(t, uint32(0xd68a0b0a), NetIPv4ToHost32(net.ParseIP("10.11.138.214")))
	}
}

func TestNetiIPAddrToHost32(t *testing.T) {
	if cpu.IsBigEndian {
		require.Equal(t, uint32(0x0a0b815b), NetIPAddrToHost32(netip.MustParseAddr("10.11.129.91")))
		require.Equal(t, uint32(0x0a0b8ad6), NetIPAddrToHost32(netip.MustParseAddr("10.11.138.214")))
	} else {
		require.Equal(t, uint32(0x5b810b0a), NetIPAddrToHost32(netip.MustParseAddr("10.11.129.91")))
		require.Equal(t, uint32(0xd68a0b0a), NetIPAddrToHost32(netip.MustParseAddr("10.11.138.214")))
	}
}
