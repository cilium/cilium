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

func (s *MonitorSuite) TestDecodeDropNotify(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(DropNotifyLen, Equals, 36)

	input := DropNotify{
		Type:     0x00,
		SubType:  0x01,
		Source:   0x02_03,
		Hash:     0x04_05_06_07,
		OrigLen:  0x08_09_0a_0b,
		CapLen:   0x0c_0d_0e_10,
		SrcLabel: 0x11_12_13_14,
		DstLabel: 0x15_16_17_18,
		DstID:    0x19_1a_1b_1c,
		Line:     0x1d_1e,
		File:     0x20,
		ExtError: 0x21,
		Ifindex:  0x22_23_24_25,
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	c.Assert(err, IsNil)

	output := &DropNotify{}
	err = DecodeDropNotify(buf.Bytes(), output)
	c.Assert(err, IsNil)

	c.Assert(output.Type, Equals, input.Type)
	c.Assert(output.SubType, Equals, input.SubType)
	c.Assert(output.Source, Equals, input.Source)
	c.Assert(output.Hash, Equals, input.Hash)
	c.Assert(output.OrigLen, Equals, input.OrigLen)
	c.Assert(output.CapLen, Equals, input.CapLen)
	c.Assert(output.SrcLabel, Equals, input.SrcLabel)
	c.Assert(output.DstLabel, Equals, input.DstLabel)
	c.Assert(output.DstID, Equals, input.DstID)
	c.Assert(output.Line, Equals, input.Line)
	c.Assert(output.File, Equals, input.File)
	c.Assert(output.ExtError, Equals, input.ExtError)
	c.Assert(output.Ifindex, Equals, input.Ifindex)
}

func BenchmarkNewDecodeDropNotify(b *testing.B) {
	input := DropNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dn := &DropNotify{}
		if err := DecodeDropNotify(buf.Bytes(), dn); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOldDecodeDropNotify(b *testing.B) {
	input := DropNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dn := &DropNotify{}
		if err := binary.Read(bytes.NewReader(buf.Bytes()), byteorder.Native, dn); err != nil {
			b.Fatal(err)
		}
	}
}
