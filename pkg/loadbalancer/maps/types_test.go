// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

func TestUnmarshalSockRevNat4Key(t *testing.T) {
	bpfMapBytes := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x61, 0x02, 0x66, 0x01, 0xbb, 0, 0}
	binary.NativeEndian.PutUint64(bpfMapBytes[:8], 16977)
	expected := *NewSockRevNat4Key(16977, net.ParseIP("10.97.2.102"), 443)
	var got SockRevNat4Key
	var out bpf.MapKey = &got
	err := unmarshalFromBpfMapBytes(out, bpfMapBytes[:])
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

func TestUnmarshalSockRevNat4Value(t *testing.T) {
	bpfMapBytes := [8]byte{0x0a, 0x60, 0x01, 0x03, 0x01, 0xbb, 0, 0}
	binary.NativeEndian.PutUint16(bpfMapBytes[6:8], 15612)
	var addr types.IPv4
	addr.FromAddr(netip.MustParseAddr("10.96.1.3"))
	var expected = SockRevNat4Value{
		Address:     addr,
		Port:        byteorder.HostToNetwork16(443),
		RevNatIndex: 15612,
	}
	var got SockRevNat4Value
	var out bpf.MapValue = &got
	err := unmarshalFromBpfMapBytes(out, bpfMapBytes[:])
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

func TestUnmarshalSockRevNat6Key(t *testing.T) {
	bpfMapBytes := [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x61, 0x02, 0x66, 0x01, 0xbb, 0, 0, 0, 0, 0, 0}
	binary.NativeEndian.PutUint64(bpfMapBytes[:8], 16977)
	expected := *NewSockRevNat6Key(16977, net.ParseIP("fd00::10.97.2.102"), 443)
	var got SockRevNat6Key
	var out bpf.MapKey = &got
	err := unmarshalFromBpfMapBytes(out, bpfMapBytes[:])
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

func TestUnmarshalSockRevNat6Value(t *testing.T) {
	bpfMapBytes := [20]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x60, 0x01, 0x03, 0x01, 0xbb, 0, 0}
	binary.NativeEndian.PutUint16(bpfMapBytes[18:], 15612)
	var addr types.IPv6
	addr.FromAddr(netip.MustParseAddr("fd00::10.96.1.3"))
	var expected = SockRevNat6Value{
		Address:     addr,
		Port:        byteorder.HostToNetwork16(443),
		RevNatIndex: 15612,
	}
	var got SockRevNat6Value
	var out bpf.MapValue = &got
	err := unmarshalFromBpfMapBytes(out, bpfMapBytes[:])
	require.NoError(t, err)
	require.Equal(t, expected, got)
}
