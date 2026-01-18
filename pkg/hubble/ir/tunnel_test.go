// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func Test_protoToTunnel(t *testing.T) {
	uu := map[string]struct {
		in *flow.Tunnel
		e  Tunnel
	}{
		"nil": {
			e: Tunnel{},
		},

		"tcp": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: &flow.IP{
					Source:       "1.1.1.1",
					Destination:  "2.2.2.2",
					IpVersion:    flow.IPVersion_IPv4,
					SourceXlated: "blee",
					Encrypted:    true,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      4789,
							DestinationPort: 4789,
						},
					},
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: IP{
					Source:       net.ParseIP("1.1.1.1"),
					Destination:  net.ParseIP("2.2.2.2"),
					IPVersion:    flow.IPVersion_IPv4,
					SourceXlated: "blee",
					Encrypted:    true,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      4789,
						DestinationPort: 4789,
					},
				},
			},
		},

		"udp": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_GENEVE,
				IP: &flow.IP{
					Source:      "2001:db8::1",
					Destination: "2001:db8::2",
					IpVersion:   flow.IPVersion_IPv6,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_UDP{
						UDP: &flow.UDP{
							SourcePort:      6081,
							DestinationPort: 6081,
						},
					},
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_GENEVE,
				IP: IP{
					Source:      net.ParseIP("2001:db8::1"),
					Destination: net.ParseIP("2001:db8::2"),
					IPVersion:   flow.IPVersion_IPv6,
				},
				L4: Layer4{
					UDP: UDP{
						SourcePort:      6081,
						DestinationPort: 6081,
					},
				},
			},
		},

		"icmpv4": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_GENEVE,
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
					IpVersion:   flow.IPVersion_IPv4,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_ICMPv4{
						ICMPv4: &flow.ICMPv4{
							Type: 4,
							Code: 0,
						},
					},
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_GENEVE,
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					ICMPv4: ICMP{
						Type: 4,
						Code: 0,
					},
				},
			},
		},

		"icmpv6": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: &flow.IP{
					Source:      "2001:db8::1",
					Destination: "2001:db8::2",
					IpVersion:   flow.IPVersion_IPv6,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_ICMPv6{
						ICMPv6: &flow.ICMPv6{
							Type: 135,
							Code: 0,
						},
					},
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: IP{
					Source:      net.ParseIP("2001:db8::1"),
					Destination: net.ParseIP("2001:db8::2"),
					IPVersion:   flow.IPVersion_IPv6,
				},
				L4: Layer4{
					ICMPv6: ICMP{
						Type: 135,
						Code: 0,
					},
				},
			},
		},

		"sctp": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
					IpVersion:   flow.IPVersion_IPv4,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_SCTP{
						SCTP: &flow.SCTP{
							SourcePort:      1234,
							DestinationPort: 5678,
						},
					},
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					SCTP: SCTP{
						SourcePort:      1234,
						DestinationPort: 5678,
					},
				},
			},
		},

		"vrrp": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_GENEVE,
				IP: &flow.IP{
					Source:      "2001:db8::1",
					Destination: "2001:db8::2",
					IpVersion:   flow.IPVersion_IPv6,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_VRRP{
						VRRP: &flow.VRRP{
							Type:     1,
							Vrid:     42,
							Priority: 100,
						},
					},
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_GENEVE,
				IP: IP{
					Source:      net.ParseIP("2001:db8::1"),
					Destination: net.ParseIP("2001:db8::2"),
					IPVersion:   flow.IPVersion_IPv6,
				},
				L4: Layer4{
					VRRP: VRRP{
						Type:     1,
						VRID:     42,
						Priority: 100,
					},
				},
			},
		},

		"igmp": {
			in: &flow.Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
					IpVersion:   flow.IPVersion_IPv4,
				},
			},
			e: Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, protoToTunnel(u.in))
		})
	}
}

func TestTunnel_toProto(t *testing.T) {
	uu := map[string]struct {
		in Tunnel
		e  *flow.Tunnel
	}{
		"empty": {
			e: nil,
		},

		"tcp": {
			in: Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: IP{
					Source:       net.ParseIP("1.1.1.1"),
					Destination:  net.ParseIP("2.2.2.2"),
					IPVersion:    flow.IPVersion_IPv4,
					SourceXlated: "3.3.3.3",
					Encrypted:    true,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      4789,
						DestinationPort: 4789,
					},
				},
			},
			e: &flow.Tunnel{
				Protocol: flow.Tunnel_VXLAN,
				IP: &flow.IP{
					Source:       "1.1.1.1",
					Destination:  "2.2.2.2",
					IpVersion:    flow.IPVersion_IPv4,
					SourceXlated: "3.3.3.3",
					Encrypted:    true,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      4789,
							DestinationPort: 4789,
						},
					},
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}
