// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"bytes"
	"testing"

	bgppacket "github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func TestFormatCaps(t *testing.T) {
	tests := []struct {
		name      string
		cap       bgppacket.ParameterCapabilityInterface
		support   string
		localCap  bgppacket.ParameterCapabilityInterface
		remoteCap bgppacket.ParameterCapabilityInterface
		want      string
	}{
		{
			name: "test-software-version-cap-both",
			cap: &bgppacket.CapSoftwareVersion{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_SOFT_VERSION,
				},
			},
			support: "advertised and received",
			localCap: &bgppacket.CapSoftwareVersion{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_SOFT_VERSION,
				},
				SoftwareVersion: "1.0.0",
			},
			remoteCap: &bgppacket.CapSoftwareVersion{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_SOFT_VERSION,
				},
				SoftwareVersion: "2.0.0",
			},
			want: "\tsoftware-version: advertised and received\n\t\tlocal:\n\t\t\t1.0.0\n\t\tremote:\n\t\t\t2.0.0\n",
		},
		{
			name: "test-default-cap-remote",
			cap: &bgppacket.DefaultParameterCapability{
				CapCode: bgppacket.BGP_CAP_FOUR_OCTET_AS_NUMBER,
			},
			support: "received",
			remoteCap: &bgppacket.DefaultParameterCapability{
				CapCode: bgppacket.BGP_CAP_FOUR_OCTET_AS_NUMBER,
			},
			want: "\t4-octet-as: received\n\t\tremote:\n\t\t\t4-octet-as\n",
		},
		{
			name: "test-fqdn-cap-local",
			cap: &bgppacket.CapFQDN{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_FQDN,
				},
			},
			support: "advertised",
			localCap: &bgppacket.CapFQDN{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_FQDN,
				},
				HostName:   "cilium",
				DomainName: "cilium.io",
			},
			want: "\tfqdn: advertised\n\t\tlocal:\n\t\t\tname: cilium\n\t\t\tdomain: cilium.io\n",
		},
		{
			name: "test-graceful-restart-cap-both",
			cap: &bgppacket.CapGracefulRestart{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_GRACEFUL_RESTART,
				},
			},
			support: "advertised and received",
			localCap: &bgppacket.CapGracefulRestart{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_GRACEFUL_RESTART,
				},
				Flags: 0x0c, // restart and notification flag
				Time:  120,
				Tuples: []*bgppacket.CapGracefulRestartTuple{
					{
						AFI:   bgppacket.AFI_IP,
						SAFI:  bgppacket.SAFI_UNICAST,
						Flags: 0x80, // forward flag
					},
				},
			},
			remoteCap: &bgppacket.CapGracefulRestart{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_GRACEFUL_RESTART,
				},
				Flags: 0x08, // restart flag
				Time:  120,
				Tuples: []*bgppacket.CapGracefulRestartTuple{
					{
						AFI:  bgppacket.AFI_IP,
						SAFI: bgppacket.SAFI_UNICAST,
					},
				},
			},
			want: "\tgraceful-restart: advertised and received\n\t\tlocal:\n \t\t\trestart time: 120 sec, restart flag set, notification flag set\n\t\t\tipv4-unicast, forward flag set\n\t\tremote:\n \t\t\trestart time: 120 sec, restart flag set\n\t\t\tipv4-unicast\n",
		},
		{
			name: "test-long-lived-graceful-restart-cap-both",
			cap: &bgppacket.CapLongLivedGracefulRestart{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART,
				},
			},
			support: "advertised and received",
			localCap: &bgppacket.CapLongLivedGracefulRestart{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART,
				},
				Tuples: []*bgppacket.CapLongLivedGracefulRestartTuple{
					{
						AFI:         bgppacket.AFI_IP,
						SAFI:        bgppacket.SAFI_UNICAST,
						Flags:       0x80, // forward flag
						RestartTime: 300,
					},
				},
			},
			remoteCap: &bgppacket.CapLongLivedGracefulRestart{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART,
				},
				Tuples: []*bgppacket.CapLongLivedGracefulRestartTuple{
					{
						AFI:         bgppacket.AFI_IP6,
						SAFI:        bgppacket.SAFI_UNICAST,
						Flags:       0,
						RestartTime: 600,
					},
				},
			},
			want: "\tlong-lived-graceful-restart: advertised and received\n\t\tlocal:\n \t\t\tipv4-unicast, restart time 300 sec, forward flag set\n\t\tremote:\n \t\t\tipv6-unicast, restart time 600 sec\n",
		},
		{
			name: "test-extended-nexthop-cap-both",
			cap: &bgppacket.CapExtendedNexthop{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_EXTENDED_NEXTHOP,
				},
			},
			support: "advertised and received",
			localCap: &bgppacket.CapExtendedNexthop{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_EXTENDED_NEXTHOP,
				},
				Tuples: []*bgppacket.CapExtendedNexthopTuple{
					{
						NLRIAFI:    bgppacket.AFI_IP,
						NLRISAFI:   bgppacket.SAFI_UNICAST,
						NexthopAFI: bgppacket.AFI_IP6,
					},
				},
			},
			remoteCap: &bgppacket.CapExtendedNexthop{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_EXTENDED_NEXTHOP,
				},
				Tuples: []*bgppacket.CapExtendedNexthopTuple{
					{
						NLRIAFI:    bgppacket.AFI_IP,
						NLRISAFI:   bgppacket.SAFI_UNICAST,
						NexthopAFI: bgppacket.AFI_IP6,
					},
				},
			},
			want: "\textended-nexthop: advertised and received\n\t\tlocal:\n \t\t\tnlri: ipv4-unicast, nexthop: ipv6\n\t\tremote:\n \t\t\tnlri: ipv4-unicast, nexthop: ipv6\n",
		},
		{
			name: "test-add-path-cap-both",
			cap: &bgppacket.CapAddPath{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_ADD_PATH,
				},
			},
			support: "advertised and received",
			localCap: &bgppacket.CapAddPath{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_ADD_PATH,
				},
				Tuples: []*bgppacket.CapAddPathTuple{
					{
						RouteFamily: bgppacket.RF_IPv4_UC,
						Mode:        bgppacket.BGP_ADD_PATH_RECEIVE,
					},
				},
			},
			remoteCap: &bgppacket.CapAddPath{
				DefaultParameterCapability: bgppacket.DefaultParameterCapability{
					CapCode: bgppacket.BGP_CAP_ADD_PATH,
				},
				Tuples: []*bgppacket.CapAddPathTuple{
					{
						RouteFamily: bgppacket.RF_IPv6_UC,
						Mode:        bgppacket.BGP_ADD_PATH_SEND,
					},
				},
			},
			want: "\tadd-path: advertised and received\n\t\tlocal:\n\t\t\tipv4-unicast: receive\n\t\tremote:\n\t\t\tipv6-unicast: send\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if formatter, found := capabilityFormatters[tt.cap.Code()]; found {
				formatter(&buf, tt.cap, tt.support, tt.localCap, tt.remoteCap)
			} else {
				formatDefaultCap(&buf, tt.cap, tt.support, tt.localCap, tt.remoteCap)
			}

			got := buf.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
