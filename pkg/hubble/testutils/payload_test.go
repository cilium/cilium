// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package testutils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// expectedPayload builds the expected output of CreateL3L4Payload by
// serializing the TraceNotify struct in native byte order (matching the
// encoding used by the function under test) and appending packet bytes.
func expectedPayload(t *testing.T, tn monitor.TraceNotify, packetLayers ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, byteorder.Native, tn))
	buf.Truncate(int(tn.DataOffset()))
	pktBuf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(pktBuf, gopacket.SerializeOptions{FixLengths: true}, packetLayers...))
	buf.Write(pktBuf.Bytes())
	return buf.Bytes()
}

func TestCreateL3L4Payload(t *testing.T) {

	// The following structs are decoded pieces of the above packets
	traceNotifyIPv4 := monitor.TraceNotify{
		Type:     monitorAPI.MessageTypeTrace,
		ObsPoint: monitorAPI.TraceToStack,
		Source:   0xba8,
		Hash:     0xd498458d,
		OrigLen:  0x62,
		CapLen:   0x62,
		SrcLabel: 0x68,
		DstLabel: 0x1,
		Reason:   monitor.TraceReasonCtReply,
		Version:  monitor.TraceNotifyVersion0,
	}
	traceNotifyIPv6 := monitor.TraceNotify{
		Type:     monitorAPI.MessageTypeTrace,
		ObsPoint: monitorAPI.TraceFromLxc,
		Source:   0xba8,
		Hash:     0xb8f2165f,
		OrigLen:  0x56,
		CapLen:   0x56,
		SrcLabel: 0x68,
		DstLabel: 0x0,
		Reason:   monitor.TraceReasonPolicy,
		Version:  monitor.TraceNotifyVersion1,
	}
	traceNotifyIPv4V2 := monitor.TraceNotify{
		Type:      monitorAPI.MessageTypeTrace,
		ObsPoint:  monitorAPI.TraceToStack,
		Source:    0xba8,
		Hash:      0xd498458d,
		OrigLen:   0x62,
		CapLen:    0x62,
		SrcLabel:  0x68,
		DstLabel:  0x1,
		Reason:    monitor.TraceReasonCtReply,
		Version:   monitor.TraceNotifyVersion2,
		IPTraceID: 0x123456789abcdef0,
	}

	etherIPv4 := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0x12, 0x91, 0x06, 0xe2, 0x22, 0x1a},
		DstMAC:       net.HardwareAddr{0x06, 0xe9, 0x18, 0x3b, 0xb2, 0x75},
	}
	etherIPv6 := &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv6,
		SrcMAC:       net.HardwareAddr{0x12, 0x91, 0x6, 0xe2, 0x22, 0x1a},
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0xff, 0x0, 0xb3, 0xe5},
	}
	etherIPv4Dot1Q := &layers.Ethernet{
		EthernetType: layers.EthernetTypeDot1Q,
		SrcMAC:       net.HardwareAddr{0x12, 0x91, 0x06, 0xe2, 0x22, 0x1a},
		DstMAC:       net.HardwareAddr{0x06, 0xe9, 0x18, 0x3b, 0xb2, 0x75},
	}
	etherIPv6Dot1Q := &layers.Ethernet{
		EthernetType: layers.EthernetTypeDot1Q,
		SrcMAC:       net.HardwareAddr{0x12, 0x91, 0x6, 0xe2, 0x22, 0x1a},
		DstMAC:       net.HardwareAddr{0x33, 0x33, 0xff, 0x0, 0xb3, 0xe5},
	}

	dot1QIPv4 := &layers.Dot1Q{
		Type:           layers.EthernetTypeIPv4,
		VLANIdentifier: 0x0202,
	}
	dot1QIPv6 := &layers.Dot1Q{
		Type:           layers.EthernetTypeIPv6,
		VLANIdentifier: 0x0202,
	}

	ipv4 := &layers.IPv4{
		Version:  0x4,
		Id:       0xbfe9,
		TTL:      63,
		Protocol: layers.IPProtocolICMPv4,
		Checksum: 0x9ae2,
		SrcIP:    net.ParseIP("1.1.1.1"),
		DstIP:    net.ParseIP("10.16.126.64"),
	}
	ipv4Rev := &layers.IPv4{
		Version:  0x4,
		Id:       0xbfe9,
		TTL:      63,
		Protocol: layers.IPProtocolICMPv4,
		Checksum: 0x9ae2,
		SrcIP:    net.ParseIP("10.16.126.64"),
		DstIP:    net.ParseIP("1.1.1.1"),
	}
	ipv6 := &layers.IPv6{
		Version:    0x6,
		NextHeader: 0x3a,
		HopLimit:   0xff,
		SrcIP:      net.ParseIP("f00d::a10:0:0:9195"),
		DstIP:      net.ParseIP("ff02::1:ff00:b3e5"),
	}
	ipv6Rev := &layers.IPv6{
		Version:    0x6,
		NextHeader: 0x3a,
		HopLimit:   0xff,
		SrcIP:      net.ParseIP("ff02::1:ff00:b3e5"),
		DstIP:      net.ParseIP("f00d::a10:0:0:9195"),
	}

	icmpv4 := &layers.ICMPv4{
		TypeCode: layers.ICMPv4TypeEchoReply,
		Checksum: 0x3639,
		Id:       0x2257,
		Seq:      0x05,
	}
	icmpv4Payload := gopacket.Payload(decodeHex("1b7b415d0000000086bf050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"))

	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeNeighborSolicitation << 8,
		Checksum: 0x5075,
	}
	icmpv6Payload := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: net.ParseIP("f00d::a10:0:0:b3e5"),
		Options: layers.ICMPv6Options{
			layers.ICMPv6Option{
				Type: layers.ICMPv6OptSourceAddress,
				Data: []uint8{0x12, 0x91, 0x6, 0xe2, 0x22, 0x1a},
			},
		},
	}

	type args struct {
		msg any
		l   []gopacket.SerializableLayer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		want    []byte
	}{
		{
			name: "ICMPv4 Echo Reply",
			args: args{
				msg: traceNotifyIPv4,
				l:   []gopacket.SerializableLayer{etherIPv4, ipv4, icmpv4, icmpv4Payload},
			},
			want: expectedPayload(t, traceNotifyIPv4, etherIPv4, ipv4, icmpv4, icmpv4Payload),
		},
		{
			name: "ICMPv6 Neighbor Solicitation",
			args: args{
				msg: traceNotifyIPv6,
				l:   []gopacket.SerializableLayer{etherIPv6, ipv6, icmpv6, icmpv6Payload},
			},
			want: expectedPayload(t, traceNotifyIPv6, etherIPv6, ipv6, icmpv6, icmpv6Payload),
		},
		{
			name: "ICMPv4 Echo Reply with IP Trace",
			args: args{
				msg: traceNotifyIPv4V2,
				l:   []gopacket.SerializableLayer{etherIPv4, ipv4, icmpv4, icmpv4Payload},
			},
			want: expectedPayload(t, traceNotifyIPv4V2, etherIPv4, ipv4, icmpv4, icmpv4Payload),
		},
		{
			name: "ICMPv4 Echo Reply Reversed",
			args: args{
				msg: traceNotifyIPv4,
				l:   []gopacket.SerializableLayer{etherIPv4, ipv4Rev, icmpv4, icmpv4Payload},
			},
			want: expectedPayload(t, traceNotifyIPv4, etherIPv4, ipv4Rev, icmpv4, icmpv4Payload),
		},
		{
			name: "ICMPv6 Neighbor Solicitation Reversed",
			args: args{
				msg: traceNotifyIPv6,
				l:   []gopacket.SerializableLayer{etherIPv6, ipv6Rev, icmpv6, icmpv6Payload},
			},
			want: expectedPayload(t, traceNotifyIPv6, etherIPv6, ipv6Rev, icmpv6, icmpv6Payload),
		},
		{
			name: "802.11q ICMPv4 Echo Reply",
			args: args{
				msg: traceNotifyIPv4,
				l:   []gopacket.SerializableLayer{etherIPv4Dot1Q, dot1QIPv4, ipv4, icmpv4, icmpv4Payload},
			},
			want: expectedPayload(t, traceNotifyIPv4, etherIPv4Dot1Q, dot1QIPv4, ipv4, icmpv4, icmpv4Payload),
		},
		{
			name: "802.11q ICMPv6 Neighbor Solicitation",
			args: args{
				msg: traceNotifyIPv6,
				l:   []gopacket.SerializableLayer{etherIPv6Dot1Q, dot1QIPv6, ipv6, icmpv6, icmpv6Payload},
			},
			want: expectedPayload(t, traceNotifyIPv6, etherIPv6Dot1Q, dot1QIPv6, ipv6, icmpv6, icmpv6Payload),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl, err := CreateL3L4Payload(tt.args.msg, tt.args.l...)
			if (err != nil) != tt.wantErr {
				t.Errorf("\"%s\" error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, pl)
		})
	}
}
