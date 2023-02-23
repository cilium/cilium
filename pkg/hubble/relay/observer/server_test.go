// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package observer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
)

func TestGetFlows(t *testing.T) {
	type results struct {
		numFlows     int
		flows        map[string][]*flowpb.Flow
		statusEvents []*relaypb.NodeStatusEvent
	}
	var got *results
	type want struct {
		flows        map[string][]*flowpb.Flow
		statusEvents []*relaypb.NodeStatusEvent
		err          error
		log          []string
	}
	fss := &testutils.FakeGRPCServerStream{
		OnContext: context.TODO,
	}
	done := make(chan struct{})
	tests := []struct {
		name   string
		plr    PeerListReporter
		ocb    observerClientBuilder
		req    *observerpb.GetFlowsRequest
		stream observerpb.Observer_GetFlowsServer
		want   want
	}{
		{
			name: "Observe 0 flows from 1 peer without address",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name:    "noip",
								Address: nil,
							},
							Conn: nil,
						},
					}
				},
				OnReportOffline: func(name string) {},
			},
			ocb: fakeObserverClientBuilder{},
			req: &observerpb.GetFlowsRequest{Number: 0},
			stream: &testutils.FakeGetFlowsServer{
				FakeGRPCServerStream: fss,
				OnSend: func(resp *observerpb.GetFlowsResponse) error {
					if resp == nil {
						return nil
					}
					switch resp.GetResponseTypes().(type) {
					case *observerpb.GetFlowsResponse_Flow:
						got.numFlows++
						got.flows[resp.GetNodeName()] = append(got.flows[resp.GetNodeName()], resp.GetFlow())
					case *observerpb.GetFlowsResponse_NodeStatus:
						got.statusEvents = append(got.statusEvents, resp.GetNodeStatus())
					}
					if got.numFlows == 0 && len(got.statusEvents) == 1 {
						close(done)
						return io.EOF
					}
					return nil
				},
			},
			want: want{
				flows: map[string][]*flowpb.Flow{},
				statusEvents: []*relaypb.NodeStatusEvent{
					{
						StateChange: relaypb.NodeState_NODE_UNAVAILABLE,
						NodeNames:   []string{"noip"},
					},
				},
				err: io.EOF,
			},
		}, {
			name: "Observe 4 flows from 2 online peers",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						},
					}
				},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					var numRecv uint64
					return &testutils.FakeObserverClient{
						OnGetFlows: func(_ context.Context, in *observerpb.GetFlowsRequest, _ ...grpc.CallOption) (observerpb.Observer_GetFlowsClient, error) {
							return &testutils.FakeGetFlowsClient{
								OnRecv: func() (*observerpb.GetFlowsResponse, error) {
									if numRecv == in.Number {
										return nil, io.EOF
									}
									numRecv++
									return &observerpb.GetFlowsResponse{
										NodeName: p.Name,
										ResponseTypes: &observerpb.GetFlowsResponse_Flow{
											Flow: &flowpb.Flow{
												NodeName: p.Name,
											},
										},
									}, nil
								},
							}, nil
						},
					}
				},
			},
			req: &observerpb.GetFlowsRequest{Number: 2},
			stream: &testutils.FakeGetFlowsServer{
				FakeGRPCServerStream: fss,
				OnSend: func(resp *observerpb.GetFlowsResponse) error {
					if resp == nil {
						return nil
					}
					switch resp.GetResponseTypes().(type) {
					case *observerpb.GetFlowsResponse_Flow:
						got.numFlows++
						got.flows[resp.GetNodeName()] = append(got.flows[resp.GetNodeName()], resp.GetFlow())
					case *observerpb.GetFlowsResponse_NodeStatus:
						got.statusEvents = append(got.statusEvents, resp.GetNodeStatus())
					}
					if got.numFlows == 4 && len(got.statusEvents) == 1 {
						close(done)
						return io.EOF
					}
					return nil
				},
			},
			want: want{
				flows: map[string][]*flowpb.Flow{
					"one": {&flowpb.Flow{NodeName: "one"}, &flowpb.Flow{NodeName: "one"}},
					"two": {&flowpb.Flow{NodeName: "two"}, &flowpb.Flow{NodeName: "two"}},
				},
				statusEvents: []*relaypb.NodeStatusEvent{
					{
						StateChange: relaypb.NodeState_NODE_CONNECTED,
						NodeNames:   []string{"one", "two"},
					},
				},
				err: io.EOF,
			},
		}, {
			name: "Observe 2 flows from 1 online peer and none from 1 unavailable peer",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.TransientFailure
								},
							},
						},
					}
				},
				OnReportOffline: func(name string) {},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					var numRecv uint64
					return &testutils.FakeObserverClient{
						OnGetFlows: func(_ context.Context, in *observerpb.GetFlowsRequest, _ ...grpc.CallOption) (observerpb.Observer_GetFlowsClient, error) {
							if p.Name != "one" {
								return nil, fmt.Errorf("GetFlows() called for peer '%s'; this is unexpected", p.Name)
							}
							return &testutils.FakeGetFlowsClient{
								OnRecv: func() (*observerpb.GetFlowsResponse, error) {
									if numRecv == in.Number {
										return nil, io.EOF
									}
									numRecv++
									return &observerpb.GetFlowsResponse{
										NodeName: p.Name,
										ResponseTypes: &observerpb.GetFlowsResponse_Flow{
											Flow: &flowpb.Flow{
												NodeName: p.Name,
											},
										},
									}, nil
								},
							}, nil
						},
					}
				},
			},
			req: &observerpb.GetFlowsRequest{Number: 2},
			stream: &testutils.FakeGetFlowsServer{
				FakeGRPCServerStream: fss,
				OnSend: func(resp *observerpb.GetFlowsResponse) error {
					if resp == nil {
						return nil
					}
					switch resp.GetResponseTypes().(type) {
					case *observerpb.GetFlowsResponse_Flow:
						got.numFlows++
						got.flows[resp.GetNodeName()] = append(got.flows[resp.GetNodeName()], resp.GetFlow())
					case *observerpb.GetFlowsResponse_NodeStatus:
						got.statusEvents = append(got.statusEvents, resp.GetNodeStatus())
					}
					if got.numFlows == 2 && len(got.statusEvents) == 2 {
						close(done)
						return io.EOF
					}
					return nil
				},
			},
			want: want{
				flows: map[string][]*flowpb.Flow{
					"one": {&flowpb.Flow{NodeName: "one"}, &flowpb.Flow{NodeName: "one"}},
				},
				statusEvents: []*relaypb.NodeStatusEvent{
					{
						StateChange: relaypb.NodeState_NODE_CONNECTED,
						NodeNames:   []string{"one"},
					}, {
						StateChange: relaypb.NodeState_NODE_UNAVAILABLE,
						NodeNames:   []string{"two"},
					},
				},
				err: io.EOF,
				log: []string{
					`level=info msg="No connection to peer two, skipping" address="192.0.2.2:4244"`,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got = &results{
				flows: make(map[string][]*flowpb.Flow),
			}
			done = make(chan struct{})
			var buf bytes.Buffer
			formatter := &logrus.TextFormatter{
				DisableColors:    true,
				DisableTimestamp: true,
			}
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetFormatter(formatter)
			logger.SetLevel(logrus.DebugLevel)

			srv, err := NewServer(
				tt.plr,
				WithLogger(logger),
				withObserverClientBuilder(tt.ocb),
			)
			assert.NoError(t, err)
			err = srv.GetFlows(tt.req, tt.stream)
			<-done
			assert.Equal(t, tt.want.err, err)
			if diff := cmp.Diff(tt.want.flows, got.flows, cmpopts.IgnoreUnexported(flowpb.Flow{})); diff != "" {
				t.Errorf("Flows mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want.statusEvents, got.statusEvents, cmpopts.IgnoreUnexported(relaypb.NodeStatusEvent{})); diff != "" {
				t.Errorf("StatusEvents mismatch (-want +got):\n%s", diff)
			}
			out := buf.String()
			for _, msg := range tt.want.log {
				assert.Contains(t, out, msg)
			}
		})
	}
}

func TestGetNodes(t *testing.T) {
	type want struct {
		resp *observerpb.GetNodesResponse
		err  error
		log  []string
	}
	tests := []struct {
		name string
		plr  PeerListReporter
		ocb  observerClientBuilder
		req  *observerpb.GetNodesRequest
		want want
	}{
		{
			name: "1 peer without address",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name:    "noip",
								Address: nil,
							},
							Conn: nil,
						},
					}
				},
				OnReportOffline: func(_ string) {},
			},
			ocb: fakeObserverClientBuilder{},
			want: want{
				resp: &observerpb.GetNodesResponse{
					Nodes: []*observerpb.Node{
						{
							Name:    "noip",
							Version: "",
							Address: "",
							State:   relaypb.NodeState_NODE_UNAVAILABLE,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						},
					},
				},
				log: []string{
					`level=info msg="No connection to peer noip, skipping" address="<nil>"`,
				},
			},
		}, {
			name: "2 connected peers",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						},
					}
				},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							switch p.Name {
							case "one":
								return &observerpb.ServerStatusResponse{
									UptimeNs:  123456,
									Version:   "cilium v1.9.0",
									MaxFlows:  4095,
									NumFlows:  4095,
									SeenFlows: 11000,
								}, nil
							case "two":
								return &observerpb.ServerStatusResponse{
									UptimeNs:  555555,
									Version:   "cilium v1.9.0",
									MaxFlows:  2047,
									NumFlows:  2020,
									SeenFlows: 12000,
								}, nil
							default:
								return nil, io.EOF
							}
						},
					}
				},
			},
			want: want{
				resp: &observerpb.GetNodesResponse{
					Nodes: []*observerpb.Node{
						{
							Name:      "one",
							Version:   "cilium v1.9.0",
							Address:   "192.0.2.1:4244",
							State:     relaypb.NodeState_NODE_CONNECTED,
							UptimeNs:  123456,
							MaxFlows:  4095,
							NumFlows:  4095,
							SeenFlows: 11000,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						}, {
							Name:      "two",
							Version:   "cilium v1.9.0",
							Address:   "192.0.2.2:4244",
							State:     relaypb.NodeState_NODE_CONNECTED,
							UptimeNs:  555555,
							MaxFlows:  2047,
							NumFlows:  2020,
							SeenFlows: 12000,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						},
					},
				},
			},
		}, {
			name: "2 connected peers with TLS",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
								TLSEnabled:    true,
								TLSServerName: "one.default.hubble-grpc.cilium.io",
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
								TLSEnabled:    true,
								TLSServerName: "two.default.hubble-grpc.cilium.io",
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						},
					}
				},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							switch p.Name {
							case "one":
								return &observerpb.ServerStatusResponse{
									UptimeNs:  123456,
									Version:   "cilium v1.9.0",
									MaxFlows:  4095,
									NumFlows:  4095,
									SeenFlows: 11000,
								}, nil
							case "two":
								return &observerpb.ServerStatusResponse{
									UptimeNs:  555555,
									Version:   "cilium v1.9.0",
									MaxFlows:  2047,
									NumFlows:  2020,
									SeenFlows: 12000,
								}, nil
							default:
								return nil, io.EOF
							}
						},
					}
				},
			},
			want: want{
				resp: &observerpb.GetNodesResponse{
					Nodes: []*observerpb.Node{
						{
							Name:      "one",
							Version:   "cilium v1.9.0",
							Address:   "192.0.2.1:4244",
							State:     relaypb.NodeState_NODE_CONNECTED,
							UptimeNs:  123456,
							MaxFlows:  4095,
							NumFlows:  4095,
							SeenFlows: 11000,
							Tls: &observerpb.TLS{
								Enabled:    true,
								ServerName: "one.default.hubble-grpc.cilium.io",
							},
						}, {
							Name:      "two",
							Version:   "cilium v1.9.0",
							Address:   "192.0.2.2:4244",
							State:     relaypb.NodeState_NODE_CONNECTED,
							UptimeNs:  555555,
							MaxFlows:  2047,
							NumFlows:  2020,
							SeenFlows: 12000,
							Tls: &observerpb.TLS{
								Enabled:    true,
								ServerName: "two.default.hubble-grpc.cilium.io",
							},
						},
					},
				},
			},
		}, {
			name: "1 connected peer, 1 unreachable peer",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.TransientFailure
								},
							},
						},
					}
				},
				OnReportOffline: func(_ string) {},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							switch p.Name {
							case "one":
								return &observerpb.ServerStatusResponse{
									UptimeNs:  123456,
									Version:   "cilium v1.9.0",
									MaxFlows:  4095,
									NumFlows:  4095,
									SeenFlows: 11000,
								}, nil
							default:
								return nil, io.EOF
							}
						},
					}
				},
			},
			want: want{
				resp: &observerpb.GetNodesResponse{
					Nodes: []*observerpb.Node{
						{
							Name:      "one",
							Version:   "cilium v1.9.0",
							Address:   "192.0.2.1:4244",
							State:     relaypb.NodeState_NODE_CONNECTED,
							UptimeNs:  123456,
							MaxFlows:  4095,
							NumFlows:  4095,
							SeenFlows: 11000,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						}, {
							Name:     "two",
							Version:  "",
							Address:  "192.0.2.2:4244",
							State:    relaypb.NodeState_NODE_UNAVAILABLE,
							UptimeNs: 0,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						},
					},
				},
				log: []string{
					`level=info msg="No connection to peer two, skipping" address="192.0.2.2:4244"`,
				},
			},
		}, {
			name: "1 connected peer, 1 unreachable peer, 1 peer with error",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.TransientFailure
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "three",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.3"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						},
					}
				},
				OnReportOffline: func(_ string) {},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							switch p.Name {
							case "one":
								return &observerpb.ServerStatusResponse{
									UptimeNs:  123456,
									Version:   "cilium v1.9.0",
									MaxFlows:  4095,
									NumFlows:  4095,
									SeenFlows: 11000,
								}, nil
							case "three":
								return nil, status.Errorf(codes.Unimplemented, "ServerStatus not implemented")
							default:
								return nil, io.EOF
							}
						},
					}
				},
			},
			want: want{
				resp: &observerpb.GetNodesResponse{
					Nodes: []*observerpb.Node{
						{
							Name:      "one",
							Version:   "cilium v1.9.0",
							Address:   "192.0.2.1:4244",
							UptimeNs:  123456,
							MaxFlows:  4095,
							NumFlows:  4095,
							SeenFlows: 11000,
							State:     relaypb.NodeState_NODE_CONNECTED,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						}, {
							Name:    "two",
							Version: "",
							Address: "192.0.2.2:4244",
							State:   relaypb.NodeState_NODE_UNAVAILABLE,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						}, {
							Name:    "three",
							Version: "",
							Address: "192.0.2.3:4244",
							State:   relaypb.NodeState_NODE_ERROR,
							Tls: &observerpb.TLS{
								Enabled:    false,
								ServerName: "",
							},
						},
					},
				},
				log: []string{
					`level=info msg="No connection to peer two, skipping" address="192.0.2.2:4244"`,
					`level=warning msg="Failed to retrieve server status" error="rpc error: code = Unimplemented desc = ServerStatus not implemented" peer=three`,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := &logrus.TextFormatter{
				DisableColors:    true,
				DisableTimestamp: true,
			}
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetFormatter(formatter)
			logger.SetLevel(logrus.DebugLevel)

			srv, err := NewServer(
				tt.plr,
				WithLogger(logger),
				withObserverClientBuilder(tt.ocb),
			)
			assert.NoError(t, err)
			got, err := srv.GetNodes(context.Background(), tt.req)
			assert.Equal(t, tt.want.err, err)
			assert.Equal(t, tt.want.resp, got)
			out := buf.String()
			for _, msg := range tt.want.log {
				assert.Contains(t, out, msg)
			}
		})
	}
}

func TestServerStatus(t *testing.T) {
	type want struct {
		resp *observerpb.ServerStatusResponse
		err  error
		log  []string
	}
	tests := []struct {
		name string
		plr  PeerListReporter
		ocb  observerClientBuilder
		req  *observerpb.ServerStatusRequest
		want want
	}{
		{
			name: "1 peer without address",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name:    "noip",
								Address: nil,
							},
							Conn: nil,
						},
					}
				},
				OnReportOffline: func(_ string) {},
			},
			ocb: fakeObserverClientBuilder{},
			want: want{
				resp: &observerpb.ServerStatusResponse{
					Version:             "hubble-relay",
					NumFlows:            0,
					MaxFlows:            0,
					SeenFlows:           0,
					UptimeNs:            0,
					NumConnectedNodes:   &wrapperspb.UInt32Value{Value: 0},
					NumUnavailableNodes: &wrapperspb.UInt32Value{Value: 1},
					UnavailableNodes:    []string{"noip"},
				},
				log: []string{
					`level=info msg="No connection to peer noip, skipping" address="<nil>"`,
				},
			},
		}, {
			name: "2 connected peers",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						},
					}
				},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							switch p.Name {
							case "one":
								return &observerpb.ServerStatusResponse{
									NumFlows:  1111,
									MaxFlows:  1111,
									SeenFlows: 1111,
									UptimeNs:  111111111,
								}, nil
							case "two":
								return &observerpb.ServerStatusResponse{
									NumFlows:  2222,
									MaxFlows:  2222,
									SeenFlows: 2222,
									UptimeNs:  222222222,
								}, nil
							default:
								return nil, io.EOF
							}
						},
					}
				},
			},
			want: want{
				resp: &observerpb.ServerStatusResponse{
					Version:             "hubble-relay",
					NumFlows:            3333,
					MaxFlows:            3333,
					SeenFlows:           3333,
					UptimeNs:            222222222,
					NumConnectedNodes:   &wrapperspb.UInt32Value{Value: 2},
					NumUnavailableNodes: &wrapperspb.UInt32Value{Value: 0},
				},
			},
		}, {
			name: "1 connected peer, 1 unreachable peer",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.Ready
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.TransientFailure
								},
							},
						},
					}
				},
				OnReportOffline: func(_ string) {},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							switch p.Name {
							case "one":
								return &observerpb.ServerStatusResponse{
									NumFlows:  1111,
									MaxFlows:  1111,
									SeenFlows: 1111,
									UptimeNs:  111111111,
								}, nil
							default:
								return nil, io.EOF
							}
						},
					}
				},
			},
			want: want{
				resp: &observerpb.ServerStatusResponse{
					Version:             "hubble-relay",
					NumFlows:            1111,
					MaxFlows:            1111,
					SeenFlows:           1111,
					UptimeNs:            111111111,
					NumConnectedNodes:   &wrapperspb.UInt32Value{Value: 1},
					NumUnavailableNodes: &wrapperspb.UInt32Value{Value: 1},
					UnavailableNodes:    []string{"two"},
				},
				log: []string{
					`level=info msg="No connection to peer two, skipping" address="192.0.2.2:4244"`,
				},
			},
		}, {
			name: "2 unreachable peers",
			plr: &testutils.FakePeerListReporter{
				OnList: func() []poolTypes.Peer {
					return []poolTypes.Peer{
						{
							Peer: peerTypes.Peer{
								Name: "one",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.1"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.TransientFailure
								},
							},
						}, {
							Peer: peerTypes.Peer{
								Name: "two",
								Address: &net.TCPAddr{
									IP:   net.ParseIP("192.0.2.2"),
									Port: defaults.ServerPort,
								},
							},
							Conn: &testutils.FakeClientConn{
								OnGetState: func() connectivity.State {
									return connectivity.TransientFailure
								},
							},
						},
					}
				},
				OnReportOffline: func(_ string) {},
			},
			ocb: fakeObserverClientBuilder{
				onObserverClient: func(p *poolTypes.Peer) observerpb.ObserverClient {
					return &testutils.FakeObserverClient{
						OnServerStatus: func(_ context.Context, in *observerpb.ServerStatusRequest, _ ...grpc.CallOption) (*observerpb.ServerStatusResponse, error) {
							return nil, io.EOF
						},
					}
				},
			},
			want: want{
				resp: &observerpb.ServerStatusResponse{
					Version:             "hubble-relay",
					NumFlows:            0,
					MaxFlows:            0,
					SeenFlows:           0,
					UptimeNs:            0,
					NumConnectedNodes:   &wrapperspb.UInt32Value{Value: 0},
					NumUnavailableNodes: &wrapperspb.UInt32Value{Value: 2},
					UnavailableNodes:    []string{"one", "two"},
				},
				log: []string{
					`level=info msg="No connection to peer one, skipping" address="192.0.2.1:4244"`,
					`level=info msg="No connection to peer two, skipping" address="192.0.2.2:4244"`,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := &logrus.TextFormatter{
				DisableColors:    true,
				DisableTimestamp: true,
			}
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetFormatter(formatter)
			logger.SetLevel(logrus.DebugLevel)

			srv, err := NewServer(
				tt.plr,
				WithLogger(logger),
				withObserverClientBuilder(tt.ocb),
			)
			assert.NoError(t, err)
			got, err := srv.ServerStatus(context.Background(), tt.req)
			assert.Equal(t, tt.want.err, err)
			assert.Equal(t, tt.want.resp, got)
			out := buf.String()
			for _, msg := range tt.want.log {
				assert.Contains(t, out, msg)
			}
		})
	}
}

type fakeObserverClientBuilder struct {
	onObserverClient func(*poolTypes.Peer) observerpb.ObserverClient
}

func (b fakeObserverClientBuilder) observerClient(p *poolTypes.Peer) observerpb.ObserverClient {
	if b.onObserverClient != nil {
		return b.onObserverClient(p)
	}
	panic("OnObserverClient not set")
}
