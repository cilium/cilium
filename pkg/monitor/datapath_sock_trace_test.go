// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

func (s *MonitorSuite) TestDecodeTraceSockNotify(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(TraceSockNotifyLen, Equals, 38)

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
	c.Assert(err, IsNil)

	output := &TraceSockNotify{}
	err = DecodeTraceSockNotify(buf.Bytes(), output)
	c.Assert(err, IsNil)

	c.Assert(output.Type, Equals, input.Type)
	c.Assert(output.XlatePoint, Equals, input.XlatePoint)
	c.Assert(output.DstIP, Equals, input.DstIP)
	c.Assert(output.DstPort, Equals, input.DstPort)
	c.Assert(output.SockCookie, Equals, input.SockCookie)
	c.Assert(output.L4Proto, Equals, input.L4Proto)
	c.Assert(output.Flags, Equals, input.Flags)
}

func BenchmarkNewDecodeTraceSockNotify(b *testing.B) {
	input := &TraceSockNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tsn := &TraceSockNotify{}
		if err := binary.Read(bytes.NewBuffer(buf.Bytes()), byteorder.Native, tsn); err != nil {
			b.Fatal(err)
		}
	}
}
