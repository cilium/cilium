// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/types"
)

func (s *MonitorSuite) TestDecodeTraceNotifyV0(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(traceNotifyV0Len, Equals, 32)

	input := TraceNotifyV0{
		Type:     0x00,
		ObsPoint: 0x02,
		Source:   0x03_04,
		Hash:     0x05_06_07_08,
		OrigLen:  0x09_0a_0b_0c,
		CapLen:   0x0d_0e,
		Version:  TraceNotifyVersion0,
		SrcLabel: identity.NumericIdentity(0x_11_12_13_14),
		DstLabel: identity.NumericIdentity(0x_15_16_17_18),
		DstID:    0x19_1a,
		Reason:   0x1b,
		Flags:    0x1c,
		Ifindex:  0x1d_1e_1f_20,
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, input)
	c.Assert(err, IsNil)

	output := TraceNotify{}
	err = DecodeTraceNotify(buf.Bytes(), &output)
	c.Assert(err, IsNil)
	c.Assert(output.Type, Equals, input.Type)
	c.Assert(output.ObsPoint, Equals, input.ObsPoint)
	c.Assert(output.Source, Equals, input.Source)
	c.Assert(output.Hash, Equals, input.Hash)
	c.Assert(output.OrigLen, Equals, input.OrigLen)
	c.Assert(output.CapLen, Equals, input.CapLen)
	c.Assert(output.Version, Equals, input.Version)
	c.Assert(output.SrcLabel, Equals, input.SrcLabel)
	c.Assert(output.DstLabel, Equals, input.DstLabel)
	c.Assert(output.DstID, Equals, input.DstID)
	c.Assert(output.Reason, Equals, input.Reason)
	c.Assert(output.Flags, Equals, input.Flags)
	c.Assert(output.Ifindex, Equals, input.Ifindex)
}

func (s *MonitorSuite) TestDecodeTraceNotifyV1(c *C) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	c.Assert(traceNotifyV1Len, Equals, 48)

	in := TraceNotifyV1{
		TraceNotifyV0: TraceNotifyV0{
			Type:     0x00,
			ObsPoint: 0x02,
			Source:   0x03_04,
			Hash:     0x05_06_07_08,
			OrigLen:  0x09_0a_0b_0c,
			CapLen:   0x0d_0e,
			Version:  TraceNotifyVersion1,
			SrcLabel: identity.NumericIdentity(0x_11_12_13_14),
			DstLabel: identity.NumericIdentity(0x_15_16_17_18),
			DstID:    0x19_1a,
			Reason:   0x1b,
			Flags:    0x1c,
			Ifindex:  0x1d_1e_1f_20,
		},
		OrigIP: types.IPv6{
			0x21, 0x22,
			0x23, 0x24,
			0x25, 0x26,
			0x27, 0x28,
			0x29, 0x2a,
		},
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, byteorder.Native, in)
	c.Assert(err, IsNil)

	out := TraceNotify{}
	err = DecodeTraceNotify(buf.Bytes(), &out)
	c.Assert(err, IsNil)
	c.Assert(out.Type, Equals, in.Type)
	c.Assert(out.ObsPoint, Equals, in.ObsPoint)
	c.Assert(out.Source, Equals, in.Source)
	c.Assert(out.Hash, Equals, in.Hash)
	c.Assert(out.OrigLen, Equals, in.OrigLen)
	c.Assert(out.CapLen, Equals, in.CapLen)
	c.Assert(out.Version, Equals, in.Version)
	c.Assert(out.SrcLabel, Equals, in.SrcLabel)
	c.Assert(out.DstLabel, Equals, in.DstLabel)
	c.Assert(out.DstID, Equals, in.DstID)
	c.Assert(out.Reason, Equals, in.Reason)
	c.Assert(out.Flags, Equals, in.Flags)
	c.Assert(out.Ifindex, Equals, in.Ifindex)
	c.Assert(out.OrigIP, Equals, in.OrigIP)
}

func (s *MonitorSuite) TestDecodeTraceNotifyErrors(c *C) {
	tn := TraceNotify{}
	err := DecodeTraceNotify([]byte{}, &tn)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "Unknown trace event")

	// invalid version
	ev := make([]byte, traceNotifyV1Len)
	ev[14] = 0xff
	err = DecodeTraceNotify(ev, &tn)
	c.Assert(err, NotNil)
	c.Assert(err.Error(), Equals, "Unrecognized trace event (version 255)")
}

func TestIsEncrypted(t *testing.T) {
	tt := []struct {
		name      string
		reason    uint8
		encrypted bool
	}{
		{
			name:      "unknown",
			reason:    TraceReasonUnknown,
			encrypted: false,
		},
		{
			name:      "unknown encrypted",
			reason:    TraceReasonUnknown | TraceReasonEncryptMask,
			encrypted: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := &TraceNotifyV0{
				Reason: tc.reason,
			}
			require.Equal(t, tc.encrypted, tn.IsEncrypted())
		})
	}
}

func TestTraceReason(t *testing.T) {
	tt := []struct {
		name   string
		reason uint8
		want   uint8
	}{
		{
			name:   "unknown",
			reason: TraceReasonUnknown,
			want:   TraceReasonUnknown,
		},
		{
			name:   "unknown encrypted",
			reason: TraceReasonUnknown | TraceReasonEncryptMask,
			want:   TraceReasonUnknown,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := &TraceNotifyV0{
				Reason: tc.reason,
			}
			require.Equal(t, tc.want, tn.TraceReason())
		})
	}
}

func TestTraceReasonIsKnown(t *testing.T) {
	tt := []struct {
		name   string
		reason uint8
		known  bool
	}{
		{
			name:   "unknown",
			reason: TraceReasonUnknown,
			known:  false,
		},
		{
			name:   "unknown encrypted",
			reason: TraceReasonUnknown | TraceReasonEncryptMask,
			known:  false,
		},
		{
			name:   "established",
			reason: TraceReasonCtEstablished,
			known:  true,
		},
		{
			name:   "established encrypted",
			reason: TraceReasonCtEstablished | TraceReasonEncryptMask,
			known:  true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := &TraceNotifyV0{
				Reason: tc.reason,
			}
			require.Equal(t, tc.known, tn.TraceReasonIsKnown())
		})
	}
}

func TestTraceReasonIsReply(t *testing.T) {
	tt := []struct {
		name   string
		reason uint8
		reply  bool
	}{
		{
			name:   "unknown",
			reason: TraceReasonUnknown,
			reply:  false,
		},
		{
			name:   "unknown encrypted",
			reason: TraceReasonUnknown | TraceReasonEncryptMask,
			reply:  false,
		},
		{
			name:   "reply",
			reason: TraceReasonCtReply,
			reply:  true,
		},
		{
			name:   "reply encrypted",
			reason: TraceReasonCtReply | TraceReasonEncryptMask,
			reply:  true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := &TraceNotifyV0{
				Reason: tc.reason,
			}
			require.Equal(t, tc.reply, tn.TraceReasonIsReply())
		})
	}
}

func TestTraceReasonIsEncap(t *testing.T) {
	tt := []struct {
		name   string
		reason uint8
		encap  bool
	}{
		{
			name:   "unknown",
			reason: TraceReasonUnknown,
			encap:  false,
		},
		{
			name:   "unknown encrypted",
			reason: TraceReasonUnknown | TraceReasonEncryptMask,
			encap:  false,
		},
		{
			name:   "srv6-encap",
			reason: TraceReasonSRv6Encap,
			encap:  true,
		},
		{
			name:   "srv6-encap encrypted",
			reason: TraceReasonSRv6Encap | TraceReasonEncryptMask,
			encap:  true,
		},
		{
			name:   "srv6-decap",
			reason: TraceReasonSRv6Decap,
			encap:  false,
		},
		{
			name:   "srv6-decap encrypted",
			reason: TraceReasonSRv6Decap | TraceReasonEncryptMask,
			encap:  false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := &TraceNotifyV0{
				Reason: tc.reason,
			}
			require.Equal(t, tc.encap, tn.TraceReasonIsEncap())
		})
	}
}

func TestTraceReasonIsDecap(t *testing.T) {
	tt := []struct {
		name   string
		reason uint8
		decap  bool
	}{
		{
			name:   "unknown",
			reason: TraceReasonUnknown,
			decap:  false,
		},
		{
			name:   "unknown encrypted",
			reason: TraceReasonUnknown | TraceReasonEncryptMask,
			decap:  false,
		},
		{
			name:   "srv6-encap",
			reason: TraceReasonSRv6Encap,
			decap:  false,
		},
		{
			name:   "srv6-encap encrypted",
			reason: TraceReasonSRv6Encap | TraceReasonEncryptMask,
			decap:  false,
		},
		{
			name:   "srv6-decap",
			reason: TraceReasonSRv6Decap,
			decap:  true,
		},
		{
			name:   "srv6-decap encrypted",
			reason: TraceReasonSRv6Decap | TraceReasonEncryptMask,
			decap:  true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			tn := &TraceNotifyV0{
				Reason: tc.reason,
			}
			require.Equal(t, tc.decap, tn.TraceReasonIsDecap())
		})
	}
}

func BenchmarkDecodeTraceNotifyVersion0(b *testing.B) {
	input := TraceNotifyV0{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tn := &TraceNotifyV0{}
		if err := tn.decodeTraceNotifyVersion0(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeTraceNotifyVersion1(b *testing.B) {
	input := TraceNotifyV1{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, byteorder.Native, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tn := &TraceNotifyV1{}
		if err := tn.decodeTraceNotifyVersion1(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}
