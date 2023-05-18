// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	. "github.com/cilium/checkmate"
)

func (s *MonitorSuite) TestDecodeTraceNotify(c *C) {
	tn := &TraceNotify{}
	err := DecodeTraceNotify([]byte{}, tn)
	c.Assert(err, NotNil)

	data := []byte{
		0x00,       // Type
		0x00,       // ObsPoint
		0x00, 0x00, // Source
		0x00, 0x00, 0x00, 0x00, // Hash
		0x00, 0x00, 0x00, 0x00, // OrigLen
		0x00, 0x00, // CapLen
		0x00, 0x00, // Version
		0x00, 0x00, 0x00, 0x00, // SrcLabel
		0x00, 0x00, 0x00, 0x00, // DstLabel
		0x00, 0x00, // DstID
		0x00,                   // Reason
		0x00,                   // Flags
		0x02, 0x00, 0x00, 0x00, // Ifindex
	}

	err = DecodeTraceNotify(data, tn)
	c.Assert(err, IsNil)
	c.Assert(tn.Version, Equals, uint16(TraceNotifyVersion0))
	c.Assert(tn.Ifindex, Equals, uint32(2))

	// add buffer space for OrigIP field
	data = append(data, make([]byte, len(tn.OrigIP))...)
	// set version to TraceNotifyVersion1
	data[14] = 0x01

	err = DecodeTraceNotify(data, tn)
	c.Assert(err, IsNil)
	c.Assert(tn.Version, Equals, uint16(TraceNotifyVersion1))
	c.Assert(tn.Ifindex, Equals, uint32(2))

	// set invalid version
	data[14] = 0xff
	err = DecodeTraceNotify(data, tn)
	c.Assert(err, NotNil)

}
