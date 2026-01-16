// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestFlowClone(t *testing.T) {
	m1, _ := net.ParseMAC("00:11:22:33:44:55")
	m2, _ := net.ParseMAC("66:77:88:99:AA:BB")

	uu := map[string]struct {
		in *Flow
		e  Flow
	}{
		"null": {
			in: nil,
		},

		"empty": {
			in: &Flow{},
		},

		"full": {
			in: &Flow{
				UUID:    "100",
				Verdict: flow.Verdict_DROPPED,
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				AuthType: flow.AuthType_DISABLED,
				Ethernet: Ethernet{
					Source:      m1,
					Destination: m2,
				},
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      1234,
						DestinationPort: 80,
					},
				},
				Tunnel: Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
			e: Flow{
				UUID:    "100",
				Verdict: flow.Verdict_DROPPED,
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				AuthType: flow.AuthType_DISABLED,
				Ethernet: Ethernet{
					Source:      m1,
					Destination: m2,
				},
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      1234,
						DestinationPort: 80,
					},
				},
				Tunnel: Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.Clone())
		})
	}
}

func TestProtoToFlow(t *testing.T) {
	m1, _ := net.ParseMAC("00:11:22:33:44:55")
	m2, _ := net.ParseMAC("66:77:88:99:AA:BB")

	tt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	uu := map[string]struct {
		in *flow.Flow
		e  *Flow
	}{
		"null": {},

		"empty": {
			in: new(flow.Flow),
			e:  &Flow{},
		},

		"full": {
			in: &flow.Flow{
				Time:    timestamppb.New(tt),
				Uuid:    "100",
				Verdict: flow.Verdict_DROPPED,
				Emitter: &flow.Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				AuthType: flow.AuthType_DISABLED,
				Ethernet: &flow.Ethernet{
					Source:      m1.String(),
					Destination: m2.String(),
				},
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
					IpVersion:   flow.IPVersion_IPv4,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      1234,
							DestinationPort: 80,
						},
					},
				},
				Tunnel: &flow.Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: &flow.Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []*flow.Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []*flow.Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
			e: &Flow{
				CreatedOn: tt,
				UUID:      "100",
				Verdict:   flow.Verdict_DROPPED,
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				AuthType: flow.AuthType_DISABLED,
				Ethernet: Ethernet{
					Source:      m1,
					Destination: m2,
				},
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      1234,
						DestinationPort: 80,
					},
				},
				Tunnel: Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
		},

		"reply": {
			in: &flow.Flow{
				Time:    timestamppb.New(tt),
				Uuid:    "100",
				Verdict: flow.Verdict_DROPPED,
				Emitter: &flow.Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				AuthType: flow.AuthType_DISABLED,
				IsReply: &wrapperspb.BoolValue{
					Value: true,
				},
				Ethernet: &flow.Ethernet{
					Source:      m1.String(),
					Destination: m2.String(),
				},
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
					IpVersion:   flow.IPVersion_IPv4,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      1234,
							DestinationPort: 80,
						},
					},
				},
				Tunnel: &flow.Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: &flow.Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []*flow.Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []*flow.Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
			e: &Flow{
				CreatedOn: tt,
				UUID:      "100",
				Verdict:   flow.Verdict_DROPPED,
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				Reply:    ReplyYes,
				AuthType: flow.AuthType_DISABLED,
				Ethernet: Ethernet{
					Source:      m1,
					Destination: m2,
				},
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      1234,
						DestinationPort: 80,
					},
				},
				Tunnel: Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
		},

		"no-reply": {
			in: &flow.Flow{
				Time:    timestamppb.New(tt),
				Uuid:    "100",
				Verdict: flow.Verdict_DROPPED,
				Emitter: &flow.Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				AuthType: flow.AuthType_DISABLED,
				IsReply: &wrapperspb.BoolValue{
					Value: false,
				},
				Ethernet: &flow.Ethernet{
					Source:      m1.String(),
					Destination: m2.String(),
				},
				IP: &flow.IP{
					Source:      "1.1.1.1",
					Destination: "2.2.2.2",
					IpVersion:   flow.IPVersion_IPv4,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      1234,
							DestinationPort: 80,
						},
					},
				},
				Tunnel: &flow.Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: &flow.Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []*flow.Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: &flow.Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []*flow.Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
			e: &Flow{
				CreatedOn: tt,
				UUID:      "100",
				Verdict:   flow.Verdict_DROPPED,
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
				Reply:    ReplyNo,
				AuthType: flow.AuthType_DISABLED,
				Ethernet: Ethernet{
					Source:      m1,
					Destination: m2,
				},
				IP: IP{
					Source:      net.ParseIP("1.1.1.1"),
					Destination: net.ParseIP("2.2.2.2"),
					IPVersion:   flow.IPVersion_IPv4,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      1234,
						DestinationPort: 80,
					},
				},
				Tunnel: Tunnel{
					Protocol: flow.Tunnel_GENEVE,
				},
				Source: Endpoint{
					ID:          100,
					Identity:    200,
					ClusterName: "fred",
					Namespace:   "ns-1",
					PodName:     "p-1",
					Labels:      []string{"a", "b"},
					Workloads: []Workload{
						{
							Name: "wk-1",
							Kind: "zorg",
						},
					},
				},
				Destination: Endpoint{
					ID:          200,
					Identity:    300,
					ClusterName: "barney",
					Namespace:   "ns-2",
					PodName:     "p-2",
					Labels:      []string{"x", "y"},
					Workloads: []Workload{
						{
							Name: "wk-2",
							Kind: "flint",
						},
					},
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToFlow(u.in))
		})
	}
}

func TestFlowToProto(t *testing.T) {
	tt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	uu := map[string]struct {
		in Flow
		e  *flow.Flow
	}{
		"src-dst": {
			in: Flow{
				CreatedOn: tt,
				Source: Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: Endpoint{
					ID:       200,
					Identity: 2000,
				},
			},
			e: &flow.Flow{
				Time: timestamppb.New(tt),
				Source: &flow.Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: &flow.Endpoint{
					ID:       200,
					Identity: 2000,
				},
			},
		},

		"l34-tcp": {
			in: Flow{
				CreatedOn: tt,
				Source: Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      8080,
						DestinationPort: 80,
					},
				},
			},
			e: &flow.Flow{
				Time: timestamppb.New(tt),
				Source: &flow.Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: &flow.Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      8080,
							DestinationPort: 80,
						},
					},
				},
			},
		},

		"l34-udp": {
			in: Flow{
				CreatedOn: tt,
				Source: Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L4: Layer4{
					UDP: UDP{
						SourcePort:      5353,
						DestinationPort: 53,
					},
				},
			},
			e: &flow.Flow{
				Time: timestamppb.New(tt),
				Source: &flow.Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: &flow.Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_UDP{
						UDP: &flow.UDP{
							SourcePort:      5353,
							DestinationPort: 53,
						},
					},
				},
			},
		},

		"l34-tcp-with-flags": {
			in: Flow{
				CreatedOn: tt,
				Source: Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L4: Layer4{
					TCP: TCP{
						SourcePort:      8080,
						DestinationPort: 80,
						Flags: TCPFlags{
							SYN: true,
							ACK: true,
						},
					},
				},
			},
			e: &flow.Flow{
				Time: timestamppb.New(tt),
				Source: &flow.Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: &flow.Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L4: &flow.Layer4{
					Protocol: &flow.Layer4_TCP{
						TCP: &flow.TCP{
							SourcePort:      8080,
							DestinationPort: 80,
							Flags: &flow.TCPFlags{
								SYN: true,
								ACK: true,
							},
						},
					},
				},
			},
		},

		"l7-http": {
			in: Flow{
				CreatedOn: tt,
				Source: Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L7: Layer7{
					Type: flow.L7FlowType_REQUEST,
					HTTP: HTTP{
						Method:   "GET",
						URL:      "http://blee.com",
						Protocol: "http",
					},
				},
			},
			e: &flow.Flow{
				Time: timestamppb.New(tt),
				Source: &flow.Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: &flow.Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L7: &flow.Layer7{
					Type: flow.L7FlowType_REQUEST,
					Record: &flow.Layer7_Http{
						Http: &flow.HTTP{
							Method:   "GET",
							Url:      "http://blee.com",
							Protocol: "http",
						},
					},
				},
			},
		},

		"l7-dns": {
			in: Flow{
				CreatedOn: tt,
				Source: Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L7: Layer7{
					Type: flow.L7FlowType_RESPONSE,
					DNS: DNS{
						Query: "blee.com",
						Ips:   []string{"1.1.1.1", "2.2.2.2"},
					},
				},
			},
			e: &flow.Flow{
				Time: timestamppb.New(tt),
				Source: &flow.Endpoint{
					ID:       100,
					Identity: 1000,
				},
				Destination: &flow.Endpoint{
					ID:       200,
					Identity: 2000,
				},
				L7: &flow.Layer7{
					Type: flow.L7FlowType_RESPONSE,
					Record: &flow.Layer7_Dns{
						Dns: &flow.DNS{
							Query: "blee.com",
							Ips:   []string{"1.1.1.1", "2.2.2.2"},
						},
					},
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.ToProto())
		})
	}
}

func TestFlowMerge(t *testing.T) {
	uu := map[string]struct {
		flow1, flow2, e *Flow
	}{
		"all-empty": {},

		"src-empty": {
			flow2: &Flow{
				UUID: "100",
			},
			e: &Flow{
				UUID: "100",
			},
		},

		"dst-empty": {
			flow1: &Flow{
				UUID: "100",
			},
			e: &Flow{
				UUID: "100",
			},
		},

		"partial": {
			flow1: &Flow{
				UUID:    "100",
				Verdict: flow.Verdict_DROPPED,
				Source: Endpoint{
					ID: 100,
				},
				Destination: Endpoint{
					ID: 200,
				},
			},
			flow2: &Flow{
				UUID:    "100",
				Verdict: flow.Verdict_ERROR,
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
			},
			e: &Flow{
				UUID:    "100",
				Verdict: flow.Verdict_ERROR,
				Source: Endpoint{
					ID: 100,
				},
				Destination: Endpoint{
					ID: 200,
				},
				Emitter: Emitter{
					Name:    "fred",
					Version: "1.0",
				},
			},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.flow1.Merge(u.flow2))
		})
	}
}

func TestFlowIsReply(t *testing.T) {
	uu := map[string]struct {
		f Flow
		e bool
	}{
		"yes": {
			f: Flow{
				Reply: ReplyYes,
			},
			e: true,
		},

		"no": {
			f: Flow{
				Reply: ReplyNo,
			},
		},

		"unknown": {
			f: Flow{},
		},
	}

	for k, u := range uu {
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.f.IsReply())
		})
	}
}

func BenchmarkFlowToProtoL4(b *testing.B) {
	tt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

	f := Flow{
		CreatedOn: tt,
		Emitter: Emitter{
			Name:    "fred",
			Version: "1.0",
		},
		Ethernet: Ethernet{
			Source:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			Destination: net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB},
		},
		Source: Endpoint{
			ID:       100,
			Identity: 1000,
		},
		Destination: Endpoint{
			ID:       200,
			Identity: 2000,
		},
		L4: Layer4{
			TCP: TCP{
				SourcePort:      8080,
				DestinationPort: 80,
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = f.ToProto()
	}
}
