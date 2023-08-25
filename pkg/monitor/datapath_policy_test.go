// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/byteorder"
)

func (s *MonitorSuite) TestDecodePolicyVerdicyNotify(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(PolicyVerdictNotifyLen, Equals, 32)

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
	c.Assert(err, IsNil)

	output := &PolicyVerdictNotify{}
	err = DecodePolicyVerdictNotify(buf.Bytes(), output)
	c.Assert(err, IsNil)

	c.Assert(output.Type, Equals, input.Type)
	c.Assert(output.SubType, Equals, input.SubType)
	c.Assert(output.Source, Equals, input.Source)
	c.Assert(output.Hash, Equals, input.Hash)
	c.Assert(output.OrigLen, Equals, input.OrigLen)
	c.Assert(output.CapLen, Equals, input.CapLen)
	c.Assert(output.Version, Equals, input.Version)
	c.Assert(output.RemoteLabel, Equals, input.RemoteLabel)
	c.Assert(output.Verdict, Equals, input.Verdict)
	c.Assert(output.DstPort, Equals, input.DstPort)
	c.Assert(output.Proto, Equals, input.Proto)
	c.Assert(output.Flags, Equals, input.Flags)
	c.Assert(output.AuthType, Equals, input.AuthType)
	c.Assert(output.Pad1, Equals, input.Pad1)
	c.Assert(output.Pad2, Equals, input.Pad2)
}

func BenchmarkNewDecodePolicyVerdictNotify(b *testing.B) {
	input := &PolicyVerdictNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pvn := &PolicyVerdictNotify{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, pvn); err != nil {
			b.Fatal(err)
		}
	}
}
