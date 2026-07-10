// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
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
	err := binary.Write(buf, binary.NativeEndian, input)
	require.NoError(t, err)

	output := &DebugCapture{}
	err = output.Decode(buf.Bytes())
	require.NoError(t, err)

	require.Equal(t, input.Type, output.Type)
	require.Equal(t, input.SubType, output.SubType)
	require.Equal(t, input.Source, output.Source)
	require.Equal(t, input.Hash, output.Hash)
	require.Equal(t, input.OrigLen, output.OrigLen)
	require.Equal(t, input.Arg1, output.Arg1)
	require.Equal(t, input.Arg2, output.Arg2)
}

func TestDecodeDebugCaptureExt(t *testing.T) {
	setTmpExtVer := func(extVer uint8, extLen uint) {
		oldLen, ok := debugCaptureExtensionLengthFromVersion[extVer]
		if !ok {
			t.Cleanup(func() { delete(debugCaptureExtensionLengthFromVersion, extVer) })
		} else {
			t.Cleanup(func() { debugCaptureExtensionLengthFromVersion[extVer] = oldLen })
		}
		debugCaptureExtensionLengthFromVersion[extVer] = extLen
	}

	setTmpExtVer(1, 4)
	setTmpExtVer(2, 8)
	setTmpExtVer(3, 16)

	tcs := []struct {
		name      string
		dc        DebugCapture
		extension []uint32
	}{
		{
			name: "no extension",
			dc: DebugCapture{
				Version:    1,
				ExtVersion: 0,
			},
		},
		{
			name: "extension 1",
			dc: DebugCapture{
				Version:    1,
				ExtVersion: 1,
			},
			extension: []uint32{
				0xC0FFEE,
			},
		},
		{
			name: "extension 2",
			dc: DebugCapture{
				Version:    1,
				ExtVersion: 2,
			},
			extension: []uint32{
				0xC0FFEE,
				0xDECAFBAD,
			},
		},
		{
			name: "extension 2",
			dc: DebugCapture{
				Version:    1,
				ExtVersion: 3,
			},
			extension: []uint32{
				0xC0FFEE,
				0xDECAFBAD,
				0xFA1AFE1,
				0xF00DF00D,
			},
		},
	}

	for _, tc := range tcs {
		buf := bytes.NewBuffer(nil)
		err := binary.Write(buf, binary.NativeEndian, tc.dc)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, tc.extension)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, uint32(0xDEADBEEF))
		require.NoError(t, err)

		output := &DebugCapture{}
		err = output.Decode(buf.Bytes())
		require.NoError(t, err)

		require.Equal(t, uint32(0xDEADBEEF), binary.NativeEndian.Uint32(buf.Bytes()[output.DataOffset():]))
	}
}

func BenchmarkNewDecodeDebugCapture(b *testing.B) {
	input := &DebugCapture{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugCapture{}
		if err := dbg.Decode(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodeDebugCapture(b *testing.B) {
	input := &DebugCapture{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugCapture{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), binary.NativeEndian, dbg); err != nil {
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
	err := binary.Write(buf, binary.NativeEndian, input)
	require.NoError(t, err)

	output := &DebugMsg{}
	err = output.Decode(buf.Bytes())
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

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugMsg{}
		if err := dbg.Decode(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodeDebugMsg(b *testing.B) {
	input := &DebugMsg{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		dbg := &DebugMsg{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), binary.NativeEndian, dbg); err != nil {
			b.Fatal(err)
		}
	}
}
