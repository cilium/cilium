// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package testutils

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"

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

func TestCreateL3L4Payload(t *testing.T) {
	// These contain TraceNotify headers plus the ethernet header of the packet
	packetv4Prefix := decodeHex("0403a80b8d4598d462000000620000006800000001000000000002000000000006e9183bb275129106e2221a080045000054bfe900003f019ae2")
	packetv4802Prefix := decodeHex("0403a80b8d4598d462000000620000006800000001000000000002000000000006e9183bb275129106e2221a81000202080045000054bfe900003f019ae2")
	packetv6Prefix := decodeHex("0405a80b5f16f2b85600000056000000680000000000000000000000000000003333ff00b3e5129106e2221a86dd6000000000203aff")
	packetv6802Prefix := decodeHex("0405a80b5f16f2b85600000056000000680000000000000000000000000000003333ff00b3e5129106e2221a8100020286dd6000000000203aff")

	// ICMPv4/v6 packets (with reversed src/dst IPs)
	packetICMPv4 := decodeHex("010101010a107e4000003639225700051b7b415d0000000086bf050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	packetICMPv6Req := decodeHex("f00d0000000000000a10000000009195ff0200000000000000000001ff00b3e58700507500000000f00d0000000000000a1000000000b3e50101129106e2221a")
	packetICMPv4Rev := decodeHex("0a107e400101010100003639225700051b7b415d0000000086bf050000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	packetICMPv6Rev := decodeHex("ff0200000000000000000001ff00b3e5f00d0000000000000a100000000091958700507500000000f00d0000000000000a1000000000b3e50101129106e2221a")

	// The following structs are decoded pieces of the above packets
	traceNotifyIPv4 := monitor.TraceNotifyV0{
		Type:     monitorAPI.MessageTypeTrace,
		ObsPoint: monitorAPI.TraceToStack,
		Source:   0xba8,
		Hash:     0xd498458d,
		OrigLen:  0x62,
		CapLen:   0x62,
		SrcLabel: 0x68,
		DstLabel: 0x1,
		Reason:   monitor.TraceReasonCtReply,
	}
	traceNotifyIPv6 := monitor.TraceNotifyV0{
		Type:     monitorAPI.MessageTypeTrace,
		ObsPoint: monitorAPI.TraceFromLxc,
		Source:   0xba8,
		Hash:     0xb8f2165f,
		OrigLen:  0x56,
		CapLen:   0x56,
		SrcLabel: 0x68,
		DstLabel: 0x0,
		Reason:   monitor.TraceReasonPolicy,
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
		msg interface{}
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
			want: append(packetv4Prefix[:], packetICMPv4...),
		},
		{
			name: "ICMPv6 Neighbor Solicitation",
			args: args{
				msg: traceNotifyIPv6,
				l:   []gopacket.SerializableLayer{etherIPv6, ipv6, icmpv6, icmpv6Payload},
			},
			want: append(packetv6Prefix[:], packetICMPv6Req...),
		},
		{
			name: "ICMPv4 Echo Reply Reversed",
			args: args{
				msg: traceNotifyIPv4,
				l:   []gopacket.SerializableLayer{etherIPv4, ipv4Rev, icmpv4, icmpv4Payload},
			},
			want: append(packetv4Prefix[:], packetICMPv4Rev...),
		},
		{
			name: "ICMPv6 Neighbor Solicitation Reversed",
			args: args{
				msg: traceNotifyIPv6,
				l:   []gopacket.SerializableLayer{etherIPv6, ipv6Rev, icmpv6, icmpv6Payload},
			},
			want: append(packetv6Prefix[:], packetICMPv6Rev...),
		},
		{
			name: "802.11q ICMPv4 Echo Reply",
			args: args{
				msg: traceNotifyIPv4,
				l:   []gopacket.SerializableLayer{etherIPv4Dot1Q, dot1QIPv4, ipv4, icmpv4, icmpv4Payload},
			},
			want: append(packetv4802Prefix[:], packetICMPv4...),
		},
		{
			name: "802.11q ICMPv6 Neighbor Solicitation",
			args: args{
				msg: traceNotifyIPv6,
				l:   []gopacket.SerializableLayer{etherIPv6Dot1Q, dot1QIPv6, ipv6, icmpv6, icmpv6Payload},
			},
			want: append(packetv6802Prefix[:], packetICMPv6Req...),
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
