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

func TestDecodeDebugCapture(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 24, DebugCaptureLen)

	input := DebugCapture{
		Type:    0x00,
		SubType: 0x01,
		Source:  0x02_03,
		Hash:    0x04_05_06_07,
		OrigLen: 0x08_09_0a_0b,
		Arg1:    0x0c_0d_0e_10,
		Arg2:    0x11_12_13_14,
	}

	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	require.NoError(t, err)

	output := &DebugCapture{}
	err = DecodeDebugCapture(buf.Bytes(), output)
	require.NoError(t, err)

	require.Equal(t, input.Type, output.Type)
	require.Equal(t, input.SubType, output.SubType)
	require.Equal(t, input.Source, output.Source)
	require.Equal(t, input.Hash, output.Hash)
	require.Equal(t, input.OrigLen, output.OrigLen)
	require.Equal(t, input.Arg1, output.Arg1)
	require.Equal(t, input.Arg2, output.Arg2)
}

func BenchmarkNewDecodeDebugCapture(b *testing.B) {
	input := &DebugCapture{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugCapture{}
		if err := DecodeDebugCapture(buf.Bytes(), dbg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodeDebugCapture(b *testing.B) {
	input := &DebugCapture{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugCapture{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, dbg); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDecodeDebugMsg(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 20, DebugMsgLen)

	input := DebugMsg{
		Type:    0x00,
		SubType: 0x01,
		Source:  0x02_03,
		Hash:    0x04_05_06_07,
		Arg1:    0x08_09_0a_0b,
		Arg2:    0x0c_0d_0e_10,
		Arg3:    0x11_12_13_14,
	}

	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	require.NoError(t, err)

	output := &DebugMsg{}
	err = DecodeDebugMsg(buf.Bytes(), output)
	require.NoError(t, err)

	require.Equal(t, input.Type, output.Type)
	require.Equal(t, input.SubType, output.SubType)
	require.Equal(t, input.Source, output.Source)
	require.Equal(t, input.Hash, output.Hash)
	require.Equal(t, input.Arg1, output.Arg1)
	require.Equal(t, input.Arg2, output.Arg2)
	require.Equal(t, input.Arg3, output.Arg3)
}

func BenchmarkNewDecodeDebugMsg(b *testing.B) {
	input := &DebugMsg{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugMsg{}
		if err := DecodeDebugMsg(buf.Bytes(), dbg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodeDebugMsg(b *testing.B) {
	input := &DebugMsg{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugMsg{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, dbg); err != nil {
			b.Fatal(err)
		}
	}
}
