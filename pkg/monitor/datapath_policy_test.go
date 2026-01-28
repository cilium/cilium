// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePolicyVerdicyNotify(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 40, PolicyVerdictNotifyLen)

	input := PolicyVerdictNotify{
		Type:        0x00,
		SubType:     0x01,
		Source:      0x02_03,
		Hash:        0x04_05_06_07,
		OrigLen:     0x08_09_0a_0b,
		CapLen:      0x0c_0d,
		Version:     0x10,
		RemoteLabel: 0x11_12_13_14,
		Verdict:     0x15_16_17_18,
		DstPort:     0x19_1a,
		Proto:       0x1b,
		Flags:       0x1c,
		AuthType:    0x1d,
		Cookie:      0x1e_1f_20_21,
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, binary.NativeEndian, input)
	require.NoError(t, err)

	output := &PolicyVerdictNotify{}
	err = output.Decode(buf.Bytes())
	require.NoError(t, err)

	require.Equal(t, input.Type, output.Type)
	require.Equal(t, input.SubType, output.SubType)
	require.Equal(t, input.Source, output.Source)
	require.Equal(t, input.Hash, output.Hash)
	require.Equal(t, input.OrigLen, output.OrigLen)
	require.Equal(t, input.CapLen, output.CapLen)
	require.Equal(t, input.Version, output.Version)
	require.Equal(t, input.RemoteLabel, output.RemoteLabel)
	require.Equal(t, input.Verdict, output.Verdict)
	require.Equal(t, input.DstPort, output.DstPort)
	require.Equal(t, input.Proto, output.Proto)
	require.Equal(t, input.Flags, output.Flags)
	require.Equal(t, input.AuthType, output.AuthType)
	require.Equal(t, input.Cookie, output.Cookie)
}

func TestDecodePolicyVerdictNotifyExtension(t *testing.T) {
	setTmpExtVer := func(extVer uint8, extLen uint) {
		oldLen, ok := policyVerdictExtensionLengthFromVersion[extVer]
		if !ok {
			t.Cleanup(func() { delete(policyVerdictExtensionLengthFromVersion, extVer) })
		} else {
			t.Cleanup(func() { policyVerdictExtensionLengthFromVersion[extVer] = oldLen })
		}
		policyVerdictExtensionLengthFromVersion[extVer] = extLen
	}

	setTmpExtVer(1, 4)
	setTmpExtVer(2, 8)
	setTmpExtVer(3, 16)

	tcs := []struct {
		name      string
		pvn       PolicyVerdictNotify
		extension []uint32
	}{
		{
			name: "no extension",
			pvn: PolicyVerdictNotify{
				Version:    1,
				ExtVersion: 0,
			},
		},
		{
			name: "extension 1",
			pvn: PolicyVerdictNotify{
				Version:    1,
				ExtVersion: 1,
			},
			extension: []uint32{
				0xC0FFEE,
			},
		},
		{
			name: "extension 2",
			pvn: PolicyVerdictNotify{
				Version:    3,
				ExtVersion: 2,
			},
			extension: []uint32{
				0xC0FFEE,
				0xDECAFBAD,
			},
		},
		{
			name: "extension 2",
			pvn: PolicyVerdictNotify{
				Version:    3,
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
		err := binary.Write(buf, binary.NativeEndian, tc.pvn)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, tc.extension)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, uint32(0xDEADBEEF))
		require.NoError(t, err)

		output := &PolicyVerdictNotify{}
		err = output.Decode(buf.Bytes())
		require.NoError(t, err)

		require.Equal(t, uint32(0xDEADBEEF), binary.NativeEndian.Uint32(buf.Bytes()[output.DataOffset():]))
	}
}

func BenchmarkNewDecodePolicyVerdictNotify(b *testing.B) {
	input := &PolicyVerdictNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		pvn := &PolicyVerdictNotify{}
		if err := pvn.Decode(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodePolicyVerdictNotify(b *testing.B) {
	input := &PolicyVerdictNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		pvn := &PolicyVerdictNotify{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), binary.NativeEndian, pvn); err != nil {
			b.Fatal(err)
		}
	}
}
