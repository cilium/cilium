// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package observer

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"

	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

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
					NumFlows:            3333,
					MaxFlows:            3333,
					SeenFlows:           3333,
					UptimeNs:            111111111,
					NumConnectedNodes:   &wrappers.UInt32Value{Value: 2},
					NumUnavailableNodes: &wrappers.UInt32Value{Value: 0},
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
					NumFlows:            1111,
					MaxFlows:            1111,
					SeenFlows:           1111,
					UptimeNs:            111111111,
					NumConnectedNodes:   &wrappers.UInt32Value{Value: 1},
					NumUnavailableNodes: &wrappers.UInt32Value{Value: 1},
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
					NumFlows:            0,
					MaxFlows:            0,
					SeenFlows:           0,
					UptimeNs:            0,
					NumConnectedNodes:   &wrappers.UInt32Value{Value: 0},
					NumUnavailableNodes: &wrappers.UInt32Value{Value: 2},
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
