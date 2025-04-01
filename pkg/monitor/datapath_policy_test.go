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

func TestDecodePolicyVerdicyNotify(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 32, PolicyVerdictNotifyLen)

	input := PolicyVerdictNotify{
		Type:        0x00,
		SubType:     0x01,
		Source:      0x02_03,
		Hash:        0x04_05_06_07,
		OrigLen:     0x08_09_0a_0b,
		CapLen:      0x0c_0d,
		Version:     0x0e_10,
		RemoteLabel: 0x11_12_13_14,
		Verdict:     0x15_16_17_18,
		DstPort:     0x19_1a,
		Proto:       0x1b,
		Flags:       0x1c,
		AuthType:    0x1d,
		Pad1:        0x1e,
		Pad2:        0x20_21,
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	require.NoError(t, err)

	output := &PolicyVerdictNotify{}
	err = DecodePolicyVerdictNotify(buf.Bytes(), output)
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
	require.Equal(t, input.Pad1, output.Pad1)
	require.Equal(t, input.Pad2, output.Pad2)
}

func BenchmarkNewDecodePolicyVerdictNotify(b *testing.B) {
	input := &PolicyVerdictNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		pvn := &PolicyVerdictNotify{}
		if err := DecodePolicyVerdictNotify(buf.Bytes(), pvn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodePolicyVerdictNotify(b *testing.B) {
	input := &PolicyVerdictNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		pvn := &PolicyVerdictNotify{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, pvn); err != nil {
			b.Fatal(err)
		}
	}
}
