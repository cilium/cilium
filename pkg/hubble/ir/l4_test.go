// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func Test_fromLayer4(t *testing.T) {
	uu := map[string]struct {
		in Layer4
		e  *flow.Layer4
	}{
		"empty": {},

		"tcp": {
			in: Layer4{
				TCP: TCP{
					SourcePort:      1234,
					DestinationPort: 80,
					Flags:           TCPFlags{SYN: true, ACK: true},
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_TCP{
					TCP: &flow.TCP{
						SourcePort:      1234,
						DestinationPort: 80,
						Flags:           &flow.TCPFlags{SYN: true, ACK: true},
					},
				},
			},
		},

		"udp": {
			in: Layer4{
				UDP: UDP{
					SourcePort:      5678,
					DestinationPort: 53,
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_UDP{
					UDP: &flow.UDP{
						SourcePort:      5678,
						DestinationPort: 53,
					},
				},
			},
		},

		"icmpv4": {
			in: Layer4{
				ICMPv4: ICMP{
					Type: 8,
					Code: 0,
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_ICMPv4{
					ICMPv4: &flow.ICMPv4{
						Type: 8,
						Code: 0,
					},
				},
			},
		},

		"icmpv6": {
			in: Layer4{
				ICMPv6: ICMP{
					Type: 135,
					Code: 0,
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_ICMPv6{
					ICMPv6: &flow.ICMPv6{
						Type: 135,
						Code: 0,
					},
				},
			},
		},

		"sctp": {
			in: Layer4{
				SCTP: SCTP{
					SourcePort:      3456,
					DestinationPort: 7890,
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_SCTP{
					SCTP: &flow.SCTP{
						SourcePort:      3456,
						DestinationPort: 7890,
					},
				},
			},
		},

		"vrrp": {
			in: Layer4{
				VRRP: VRRP{
					Type:     1,
					VRID:     42,
					Priority: 100,
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_VRRP{
					VRRP: &flow.VRRP{
						Type:     1,
						Vrid:     42,
						Priority: 100,
					},
				},
			},
		},

		"igmp": {
			in: Layer4{
				IGMP: IGMP{
					Type:         2,
					GroupAddress: "224.0.0.1",
				},
			},
			e: &flow.Layer4{
				Protocol: &flow.Layer4_IGMP{
					IGMP: &flow.IGMP{
						Type:         2,
						GroupAddress: "224.0.0.1",
					},
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func Test_toLayer4(t *testing.T) {
	uu := map[string]struct {
		in *flow.Layer4
		e  Layer4
	}{
		"empty": {
			e: Layer4{},
		},

		"tcp": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_TCP{
					TCP: &flow.TCP{
						SourcePort:      1234,
						DestinationPort: 80,
						Flags:           &flow.TCPFlags{SYN: true, ACK: true},
					},
				},
			},
			e: Layer4{
				TCP: TCP{
					SourcePort:      1234,
					DestinationPort: 80,
					Flags:           TCPFlags{SYN: true, ACK: true},
				},
			},
		},

		"udp": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_UDP{
					UDP: &flow.UDP{
						SourcePort:      5678,
						DestinationPort: 53,
					},
				},
			},
			e: Layer4{
				UDP: UDP{
					SourcePort:      5678,
					DestinationPort: 53,
				},
			},
		},

		"icmpv4": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_ICMPv4{
					ICMPv4: &flow.ICMPv4{
						Type: 8,
						Code: 0,
					},
				},
			},
			e: Layer4{
				ICMPv4: ICMP{
					Type: 8,
					Code: 0,
				},
			},
		},

		"icmpv6": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_ICMPv6{
					ICMPv6: &flow.ICMPv6{
						Type: 135,
						Code: 0,
					},
				},
			},
			e: Layer4{
				ICMPv6: ICMP{
					Type: 135,
					Code: 0,
				},
			},
		},

		"sctp": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_SCTP{
					SCTP: &flow.SCTP{
						SourcePort:      3456,
						DestinationPort: 7890,
					},
				},
			},
			e: Layer4{
				SCTP: SCTP{
					SourcePort:      3456,
					DestinationPort: 7890,
				},
			},
		},

		"vrrp": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_VRRP{
					VRRP: &flow.VRRP{
						Type:     1,
						Vrid:     42,
						Priority: 100,
					},
				},
			},
			e: Layer4{
				VRRP: VRRP{
					Type:     1,
					VRID:     42,
					Priority: 100,
				},
			},
		},

		"igmp": {
			in: &flow.Layer4{
				Protocol: &flow.Layer4_IGMP{
					IGMP: &flow.IGMP{
						Type:         2,
						GroupAddress: "1.2.3.4",
					},
				},
			},
			e: Layer4{
				IGMP: IGMP{
					Type:         2,
					GroupAddress: "1.2.3.4",
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToL4(u.in))
		})
	}
}

func TestTCPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in TCP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: TCP{
				SourcePort:      1234,
				DestinationPort: 4567,
				Flags:           TCPFlags{SYN: true},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestTCP_toProto(t *testing.T) {
	uu := map[string]struct {
		in TCP
		e  *flow.TCP
	}{
		"empty": {},

		"full": {
			in: TCP{
				SourcePort:      1234,
				DestinationPort: 4567,
				Flags:           TCPFlags{SYN: true},
			},
			e: &flow.TCP{
				SourcePort:      1234,
				DestinationPort: 4567,
				Flags:           &flow.TCPFlags{SYN: true},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestTCP_protoToTCP(t *testing.T) {
	uu := map[string]struct {
		in *flow.TCP
		e  TCP
	}{
		"empty": {},
		"full": {
			in: &flow.TCP{
				SourcePort:      1234,
				DestinationPort: 4567,
				Flags:           &flow.TCPFlags{SYN: true},
			},
			e: TCP{
				SourcePort:      1234,
				DestinationPort: 4567,
				Flags:           TCPFlags{SYN: true},
			},
		},
	}
	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToTCP(u.in))
		})
	}
}

func TestUDPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in UDP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: UDP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestUDP_toProto(t *testing.T) {
	uu := map[string]struct {
		in UDP
		e  *flow.UDP
	}{
		"empty": {},

		"full": {
			in: UDP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
			e: &flow.UDP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func Test_protoToUDP(t *testing.T) {
	uu := map[string]struct {
		in *flow.UDP
		e  UDP
	}{
		"empty": {},

		"full": {
			in: &flow.UDP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
			e: UDP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToUDP(u.in))
		})
	}
}

func TestIGMPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in IGMP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: IGMP{
				Type:         1,
				GroupAddress: "bozo",
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestIGMP_toProto(t *testing.T) {
	uu := map[string]struct {
		in IGMP
		e  *flow.IGMP
	}{
		"empty": {},

		"full": {
			in: IGMP{
				Type:         1,
				GroupAddress: "bozo",
			},
			e: &flow.IGMP{
				Type:         1,
				GroupAddress: "bozo",
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func Test_protoToIGMP(t *testing.T) {
	uu := map[string]struct {
		in *flow.IGMP
		e  IGMP
	}{
		"empty": {},

		"full": {
			in: &flow.IGMP{
				Type:         1,
				GroupAddress: "bozo",
			},
			e: IGMP{
				Type:         1,
				GroupAddress: "bozo",
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToIGMP(u.in))
		})
	}
}

func TestVRRPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in VRRP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: VRRP{
				Type:     1,
				VRID:     2,
				Priority: 3,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestVRRP_toProto(t *testing.T) {
	uu := map[string]struct {
		in VRRP
		e  *flow.VRRP
	}{
		"empty": {},

		"full": {
			in: VRRP{
				Type:     1,
				VRID:     2,
				Priority: 3,
			},
			e: &flow.VRRP{
				Type:     1,
				Vrid:     2,
				Priority: 3,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func Test_protoToVRRP(t *testing.T) {
	uu := map[string]struct {
		in *flow.VRRP
		e  VRRP
	}{
		"empty": {},

		"full": {
			in: &flow.VRRP{
				Type:     1,
				Vrid:     2,
				Priority: 3,
			},
			e: VRRP{
				Type:     1,
				VRID:     2,
				Priority: 3,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToVRRP(u.in))
		})
	}
}

func TestSCTPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in SCTP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: SCTP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestSCTYP_toProto(t *testing.T) {
	uu := map[string]struct {
		in SCTP
		e  *flow.SCTP
	}{
		"empty": {},

		"full": {
			in: SCTP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
			e: &flow.SCTP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func Test_protoToSCTP(t *testing.T) {
	uu := map[string]struct {
		in *flow.SCTP
		e  SCTP
	}{
		"empty": {},

		"full": {
			in: &flow.SCTP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
			e: SCTP{
				SourcePort:      1234,
				DestinationPort: 4567,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToSCTP(u.in))
		})
	}
}

func TestICMPIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in ICMP
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: ICMP{
				Type: 8,
				Code: 100,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestICMP_toProtoV4(t *testing.T) {
	uu := map[string]struct {
		in ICMP
		e  *flow.ICMPv4
	}{
		"empty": {},

		"full": {
			in: ICMP{
				Type: 8,
				Code: 100,
			},
			e: &flow.ICMPv4{
				Type: 8,
				Code: 100,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProtoV4())
		})
	}
}

func TestICMP_toProtoV6(t *testing.T) {
	uu := map[string]struct {
		in ICMP
		e  *flow.ICMPv6
	}{
		"empty": {},

		"full": {
			in: ICMP{
				Type: 135,
				Code: 0,
			},
			e: &flow.ICMPv6{
				Type: 135,
				Code: 0,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProtoV6())
		})
	}
}

func Test_protoToICMPv4(t *testing.T) {
	uu := map[string]struct {
		in *flow.ICMPv4
		e  ICMP
	}{
		"empty": {},

		"full": {
			in: &flow.ICMPv4{
				Type: 8,
				Code: 100,
			},
			e: ICMP{
				Type: 8,
				Code: 100,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToICMPv4(u.in))
		})
	}
}

func Test_protoToICMPv6(t *testing.T) {
	uu := map[string]struct {
		in *flow.ICMPv6
		e  ICMP
	}{
		"empty": {},

		"full": {
			in: &flow.ICMPv6{
				Type: 135,
				Code: 0,
			},
			e: ICMP{
				Type: 135,
				Code: 0,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToICMPv6(u.in))
		})
	}
}

func TestTCPFlagsIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in TCPFlags
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: TCPFlags{
				SYN: true,
				FIN: true,
				ACK: true,
				RST: true,
				PSH: true,
				URG: true,
				ECE: true,
				CWR: true,
				NS:  true,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestTCPFlags_toProto(t *testing.T) {
	uu := map[string]struct {
		in TCPFlags
		e  *flow.TCPFlags
	}{
		"empty": {},

		"full": {
			in: TCPFlags{
				SYN: true,
				FIN: true,
				ACK: true,
			},
			e: &flow.TCPFlags{
				SYN: true,
				FIN: true,
				ACK: true,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func Test_protoToTCPFlags(t *testing.T) {
	uu := map[string]struct {
		in *flow.TCP
		e  TCPFlags
	}{
		"empty": {},

		"full": {
			in: &flow.TCP{
				Flags: &flow.TCPFlags{
					SYN: true,
					FIN: true,
					ACK: true,
				},
			},
			e: TCPFlags{
				SYN: true,
				FIN: true,
				ACK: true,
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, protoToTCPFlags(u.in))
		})
	}
}
