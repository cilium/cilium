// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

func TestDecodeTraceSockNotify(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 38, TraceSockNotifyLen)

	input := TraceSockNotify{
		Type:       0x00,
		XlatePoint: 0x01,
		DstIP: types.IPv6{
			0x02, 0x03,
			0x04, 0x05,
			0x06, 0x07,
			0x08, 0x09,
			0x0a, 0x0b,
			0x0c, 0x0d,
			0x0e, 0x10,
			0x11, 0x12,
		},
		DstPort:    0x13_14,
		SockCookie: 0x15_16_17_18,
		L4Proto:    0x19,
		Flags:      0x1a,
	}

	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	require.NoError(t, err)

	output := &TraceSockNotify{}
	err = DecodeTraceSockNotify(buf.Bytes(), output)
	require.NoError(t, err)

	require.Equal(t, input.Type, output.Type)
	require.Equal(t, input.XlatePoint, output.XlatePoint)
	require.Equal(t, input.DstIP, output.DstIP)
	require.Equal(t, input.DstPort, output.DstPort)
	require.Equal(t, input.SockCookie, output.SockCookie)
	require.Equal(t, input.L4Proto, output.L4Proto)
	require.Equal(t, input.Flags, output.Flags)
}

func BenchmarkNewDecodeTraceSockNotify(b *testing.B) {
	input := &TraceSockNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		tsn := &TraceSockNotify{}
		if err := DecodeTraceSockNotify(buf.Bytes(), tsn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodeTraceSockNotify(b *testing.B) {
	input := &TraceSockNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		tsn := &TraceSockNotify{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, tsn); err != nil {
			b.Fatal(err)
		}
	}
}
