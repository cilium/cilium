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

func (s *MonitorSuite) TestDecodeDebugCapture(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(DebugCaptureLen, Equals, 24)

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
	c.Assert(err, IsNil)

	output := &DebugCapture{}
	err = DecodeDebugCapture(buf.Bytes(), output)
	c.Assert(err, IsNil)

	c.Assert(output.Type, Equals, input.Type)
	c.Assert(output.SubType, Equals, input.SubType)
	c.Assert(output.Source, Equals, input.Source)
	c.Assert(output.Hash, Equals, input.Hash)
	c.Assert(output.OrigLen, Equals, input.OrigLen)
	c.Assert(output.Arg1, Equals, input.Arg1)
	c.Assert(output.Arg2, Equals, input.Arg2)
}

func BenchmarkNewDecodeDebugCapture(b *testing.B) {
	input := &DebugCapture{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dbg := &DebugCapture{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, dbg); err != nil {
			b.Fatal(err)
		}
	}
}

func (s *MonitorSuite) TestDecodeDebugMsg(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(DebugMsgLen, Equals, 20)

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
	c.Assert(err, IsNil)

	output := &DebugMsg{}
	err = DecodeDebugMsg(buf.Bytes(), output)
	c.Assert(err, IsNil)

	c.Assert(output.Type, Equals, input.Type)
	c.Assert(output.SubType, Equals, input.SubType)
	c.Assert(output.Source, Equals, input.Source)
	c.Assert(output.Hash, Equals, input.Hash)
	c.Assert(output.Arg1, Equals, input.Arg1)
	c.Assert(output.Arg2, Equals, input.Arg2)
	c.Assert(output.Arg3, Equals, input.Arg3)
}

func BenchmarkNewDecodeDebugMsg(b *testing.B) {
	input := &DebugMsg{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		dbg := &DebugMsg{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, dbg); err != nil {
			b.Fatal(err)
		}
	}
}
