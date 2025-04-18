// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
)

func TestDecodeDropNotify(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 40, dropNotifyV2Len)

	input := DropNotify{
		Type:     0x00,
		SubType:  0x01,
		Source:   0x02_03,
		Hash:     0x04_05_06_07,
		OrigLen:  0x08_09_0a_0b,
		CapLen:   0x0c_0d,
		Version:  0x02,
		SrcLabel: 0x11_12_13_14,
		DstLabel: 0x15_16_17_18,
		DstID:    0x19_1a_1b_1c,
		Line:     0x1d_1e,
		File:     0x20,
		ExtError: 0x21,
		Ifindex:  0x22_23_24_25,
		Flags:    DropNotifyFlagIsIPv6 | DropNotifyFlagIsL3Device,
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	require.NoError(t, err)

	output := &DropNotify{}
	err = DecodeDropNotify(buf.Bytes(), output)
	require.NoError(t, err)

	require.Equal(t, input.Type, output.Type)
	require.Equal(t, input.SubType, output.SubType)
	require.Equal(t, input.Source, output.Source)
	require.Equal(t, input.Hash, output.Hash)
	require.Equal(t, input.OrigLen, output.OrigLen)
	require.Equal(t, input.CapLen, output.CapLen)
	require.Equal(t, input.SrcLabel, output.SrcLabel)
	require.Equal(t, input.DstLabel, output.DstLabel)
	require.Equal(t, input.DstID, output.DstID)
	require.Equal(t, input.Line, output.Line)
	require.Equal(t, input.File, output.File)
	require.Equal(t, input.ExtError, output.ExtError)
	require.Equal(t, input.Ifindex, output.Ifindex)
	require.Equal(t, input.Flags, output.Flags)
	require.True(t, output.IsL3Device())
	require.True(t, output.IsIPv6())
}

func TestDecodeDropNotifyErrors(t *testing.T) {
	n := DropNotify{}
	err := DecodeDropNotify([]byte{}, &n)
	require.Error(t, err)
	require.Equal(t, "unexpected DropNotify data length, expected at least 36 but got 0", err.Error())

	// invalid version
	ev := make([]byte, dropNotifyV2Len)
	ev[14] = 0xff
	err = DecodeDropNotify(ev, &n)
	require.Error(t, err)
	require.Equal(t, "Unrecognized drop event (version 255)", err.Error())
}

func BenchmarkDecodeDropNotifyV1(b *testing.B) {
	input := DropNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dn := &DropNotify{}
		if err := DecodeDropNotify(buf.Bytes(), dn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeDropNotifyV2(b *testing.B) {
	input := DropNotify{Version: DropNotifyVersion2}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dn := &DropNotify{}
		if err := DecodeDropNotify(buf.Bytes(), dn); err != nil {
			b.Fatal(err)
		}
	}
}
