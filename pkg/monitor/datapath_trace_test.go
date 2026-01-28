// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/types"
)

func TestDecodeTraceNotify(t *testing.T) {
	// This check on the struct length constant is there to ensure that this
	// test is updated when the struct changes.
	require.Equal(t, 56, traceNotifyV2Len)

	in := TraceNotify{
		Type:     0x00,
		ObsPoint: 0x02,
		Source:   0x03_04,
		Hash:     0x05_06_07_08,
		OrigLen:  0x09_0a_0b_0c,
		CapLen:   0x0d_0e,
		Version:  TraceNotifyVersion2,
		SrcLabel: identity.NumericIdentity(0x11_12_13_14),
		DstLabel: identity.NumericIdentity(0x15_16_17_18),
		DstID:    0x19_1a,
		Reason:   0x1b,
		Flags:    0x1c,
		Ifindex:  0x1d_1e_1f_20,
		OrigIP: types.IPv6{
			0x21, 0x22, 0x23, 0x24,
			0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c,
			0x2d, 0x2e, 0x2f, 0x30,
		},
		IPTraceID: 0x2b_2c_2d_2e_2f_30_31_32,
	}
	buf := bytes.NewBuffer(nil)
	err := binary.Write(buf, binary.NativeEndian, in)
	require.NoError(t, err)

	out := TraceNotify{}
	err = out.Decode(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, in.Type, out.Type)
	require.Equal(t, in.ObsPoint, out.ObsPoint)
	require.Equal(t, in.Source, out.Source)
	require.Equal(t, in.Hash, out.Hash)
	require.Equal(t, in.OrigLen, out.OrigLen)
	require.Equal(t, in.CapLen, out.CapLen)
	require.Equal(t, in.Version, out.Version)
	require.Equal(t, in.SrcLabel, out.SrcLabel)
	require.Equal(t, in.DstLabel, out.DstLabel)
	require.Equal(t, in.DstID, out.DstID)
	require.Equal(t, in.Reason, out.Reason)
	require.Equal(t, in.Flags, out.Flags)
	require.Equal(t, in.Ifindex, out.Ifindex)
	require.Equal(t, in.OrigIP, out.OrigIP)
	require.Equal(t, in.IPTraceID, out.IPTraceID)
}

func TestDecodeTraceNotifyExtension(t *testing.T) {
	setTmpExtVer := func(extVer uint8, extLen uint) {
		oldLen, ok := traceNotifyExtensionLengthFromVersion[extVer]
		if !ok {
			t.Cleanup(func() { delete(traceNotifyExtensionLengthFromVersion, extVer) })
		} else {
			t.Cleanup(func() { traceNotifyExtensionLengthFromVersion[extVer] = oldLen })
		}
		traceNotifyExtensionLengthFromVersion[extVer] = extLen
	}

	setTmpExtVer(1, 4)
	setTmpExtVer(2, 8)
	setTmpExtVer(3, 16)

	tcs := []struct {
		name      string
		tn        TraceNotify
		extension []uint32
	}{
		{
			name: "no extension",
			tn: TraceNotify{
				Version:    TraceNotifyVersion2,
				ExtVersion: 0,
			},
		},
		{
			name: "extension 1",
			tn: TraceNotify{
				Version:    TraceNotifyVersion2,
				ExtVersion: 1,
			},
			extension: []uint32{
				0xC0FFEE,
			},
		},
		{
			name: "extension 2",
			tn: TraceNotify{
				Version:    TraceNotifyVersion2,
				ExtVersion: 2,
			},
			extension: []uint32{
				0xC0FFEE,
				0xDECAFBAD,
			},
		},
		{
			name: "extension 2",
			tn: TraceNotify{
				Version:    TraceNotifyVersion2,
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
		err := binary.Write(buf, binary.NativeEndian, tc.tn)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, tc.extension)
		require.NoError(t, err)
		err = binary.Write(buf, binary.NativeEndian, uint32(0xDEADBEEF))
		require.NoError(t, err)

		output := &TraceNotify{}
		err = output.Decode(buf.Bytes())
		require.NoError(t, err)

		require.Equal(t, uint32(0xDEADBEEF), binary.NativeEndian.Uint32(buf.Bytes()[output.DataOffset():]))
	}
}

func TestDecodeTraceNotifyErrors(t *testing.T) {
	tn := TraceNotify{}
	err := tn.Decode([]byte{})
	require.Error(t, err)
	require.Equal(t, "unexpected TraceNotify data length, expected at least 32 but got 0", err.Error())

	// invalid version
	ev := make([]byte, traceNotifyV1Len)
	ev[14] = 0xff
	err = tn.Decode(ev)
	require.Error(t, err)
	require.Equal(t, "Unrecognized trace event (version 255)", err.Error())
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
			tn := &TraceNotify{
				Reason: tc.reason,
			}
			require.Equal(t, tc.encrypted, tn.IsEncrypted())
		})
	}
}

func TestTraceFlags(t *testing.T) {
	tn := &TraceNotify{
		Flags: 0x0f,
	}
	require.True(t, tn.IsIPv6())
	require.True(t, tn.IsL3Device())
	require.True(t, tn.IsVXLAN())
	require.True(t, tn.IsGeneve())
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
			tn := &TraceNotify{
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
			tn := &TraceNotify{
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
			tn := &TraceNotify{
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
			tn := &TraceNotify{
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
			tn := &TraceNotify{
				Reason: tc.reason,
			}
			require.Equal(t, tc.decap, tn.TraceReasonIsDecap())
		})
	}
}

func BenchmarkDecodeTraceNotifyVersion0(b *testing.B) {
	input := TraceNotify{}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		tn := &TraceNotify{}
		if err := tn.Decode(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeTraceNotifyVersion1(b *testing.B) {
	input := TraceNotify{
		Version: TraceNotifyVersion1,
	}
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.NativeEndian, input); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()

	for b.Loop() {
		tn := &TraceNotify{
			Version: TraceNotifyVersion1,
		}
		if err := tn.Decode(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}
