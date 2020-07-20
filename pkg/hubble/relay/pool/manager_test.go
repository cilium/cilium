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

package pool

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	hubblePeer "github.com/cilium/cilium/pkg/hubble/peer"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func TestManager(t *testing.T) {
	var done chan struct{}
	tests := []struct {
		name      string
		pcBuilder peerTypes.ClientBuilder
		ccBuilder ClientConnBuilder
		want      []Peer
	}{
		{
			name: "empty pool",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							var once sync.Once
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									once.Do(func() {
										close(done)
									})
									return nil, nil
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			want: nil,
		}, {
			name: "1 unreachable peer",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							i := -1
							cns := []*peerpb.ChangeNotification{
								{
									Name:    "unreachable",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								},
							}
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									i++
									switch {
									case i >= len(cns):
										return nil, nil
									case i == len(cns)-1:
										defer func() {
											close(done)
										}()
										fallthrough
									default:
										return cns[i], nil
									}
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					return FakeClientConn{}, nil
				},
			},
			want: []Peer{
				{
					hubblePeer.Peer{
						Name: "unreachable",
						Address: &net.TCPAddr{
							IP:   net.ParseIP("192.0.1.1"),
							Port: defaults.ServerPort,
						},
					},
					nil,
				},
			},
		}, {
			name: "1 reachable peer",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							i := -1
							cns := []*peerpb.ChangeNotification{
								{
									Name:    "reachable",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								},
							}
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									i++
									switch {
									case i >= len(cns):
										return nil, nil
									default:
										return cns[i], nil
									}
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					var once sync.Once
					return FakeClientConn{
						OnGetState: func() connectivity.State {
							once.Do(func() {
								close(done)
							})
							return connectivity.Ready
						},
					}, nil
				},
			},
			want: []Peer{
				{
					hubblePeer.Peer{
						Name: "reachable",
						Address: &net.TCPAddr{
							IP:   net.ParseIP("192.0.1.1"),
							Port: defaults.ServerPort,
						},
					},
					FakeClientConn{},
				},
			},
		}, {
			name: "1 peer is deleted",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							i := -1
							cns := []*peerpb.ChangeNotification{
								{
									Name:    "reachable",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								}, {
									Name:    "reachable",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_DELETED,
								},
							}
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									i++
									switch {
									case i >= len(cns):
										return nil, nil
									case i == len(cns)-1:
										defer func() {
											close(done)
										}()
										<-time.After(10 * time.Millisecond)
										fallthrough
									default:
										return cns[i], nil
									}
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					return FakeClientConn{
						OnGetState: func() connectivity.State {
							return connectivity.Ready
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
		}, {
			name: "1 peer in transient failure",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							i := -1
							cns := []*peerpb.ChangeNotification{
								{
									Name:    "unreachable",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								},
							}
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									i++
									switch {
									case i >= len(cns):
										return nil, nil
									default:
										return cns[i], nil
									}
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					var once sync.Once
					return FakeClientConn{
						OnGetState: func() connectivity.State {
							return connectivity.TransientFailure
						},
						OnClose: func() error {
							once.Do(func() {
								close(done)
							})
							return nil
						},
					}, nil
				},
			},
			want: []Peer{
				{
					hubblePeer.Peer{
						Name: "unreachable",
						Address: &net.TCPAddr{
							IP:   net.ParseIP("192.0.1.1"),
							Port: defaults.ServerPort,
						},
					},
					FakeClientConn{},
				},
			},
		}, {
			name: "1 peer added then modified",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							i := -1
							cns := []*peerpb.ChangeNotification{
								{
									Name:    "reachable",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								}, {
									Name:    "reachable",
									Address: "192.0.5.5",
									Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
								},
							}
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									i++
									switch {
									case i >= len(cns):
										return nil, nil
									default:
										return cns[i], nil
									}
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					var i int
					return FakeClientConn{
						OnGetState: func() connectivity.State {
							i++
							if i == 2 {
								defer func() {
									close(done)
								}()
							}
							return connectivity.Ready
						},
					}, nil
				},
			},
			want: []Peer{
				{
					hubblePeer.Peer{
						Name: "reachable",
						Address: &net.TCPAddr{
							IP:   net.ParseIP("192.0.5.5"),
							Port: defaults.ServerPort,
						},
					},
					FakeClientConn{},
				},
			},
		}, {
			name: "2 peers added, 1 deleted",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							i := -1
							cns := []*peerpb.ChangeNotification{
								{
									Name:    "one",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								}, {
									Name:    "two",
									Address: "192.0.1.2",
									Type:    peerpb.ChangeNotificationType_PEER_ADDED,
								}, {
									Name:    "one",
									Address: "192.0.1.1",
									Type:    peerpb.ChangeNotificationType_PEER_DELETED,
								},
							}
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									i++
									switch {
									case i >= len(cns):
										return nil, nil
									case i == len(cns)-1:
										defer func() {
											close(done)
										}()
										fallthrough
									default:
										return cns[i], nil
									}
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					return nil, nil
				},
			},
			want: []Peer{
				{
					hubblePeer.Peer{
						Name: "two",
						Address: &net.TCPAddr{
							IP:   net.ParseIP("192.0.1.2"),
							Port: defaults.ServerPort,
						},
					},
					nil,
				},
			},
		}, {
			name: "PeerClientBuilder errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					defer func() {
						close(done)
					}()
					return nil, errors.New("I'm on PTO")
				},
			},
		}, {
			name: "ClientConnBuilder errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							var once sync.Once
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									once.Do(func() {
										<-time.After(100 * time.Millisecond)
										close(done)
									})
									return &peerpb.ChangeNotification{
										Name:    "unreachable",
										Address: "192.0.1.1",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									}, nil
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target string) (ClientConn, error) {
					return nil, errors.New("Don't feel like workin' today")
				},
			},
			want: []Peer{
				{
					hubblePeer.Peer{
						Name: "unreachable",
						Address: &net.TCPAddr{
							IP:   net.ParseIP("192.0.1.1"),
							Port: defaults.ServerPort,
						},
					},
					nil,
				},
			},
		}, {
			name: "peer notify errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					var once sync.Once
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							once.Do(func() {
								close(done)
							})
							return nil, errors.New("Don't feel like workin' today")
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
		}, {
			name: "peer recv errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							var once sync.Once
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									once.Do(func() {
										close(done)
									})
									return nil, errors.New("Nope, ain't doin' nothin'")
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done = make(chan struct{})
			mgr, err := NewManager(
				WithPeerClientBuilder(tt.pcBuilder),
				WithClientConnBuilder(tt.ccBuilder),
				WithConnCheckInterval(1*time.Second),
			)
			assert.NoError(t, err)
			mgr.Start()
			defer mgr.Stop()
			<-done
			got := mgr.List()
			// the objects are not easily compared -> hack the assertion
			assert.Equal(t, len(tt.want), len(got))
			sort.Sort(ByName(got))
			sort.Sort(ByName(tt.want))
			for i := range got {
				if tt.want[i].Conn == nil {
					assert.Nil(t, got[i].Conn)
				}
				// we only care whether this field is <nil> or not (tested above)
				// as this field is not easily compared, hack it so that we can
				// still assert the rest of the struct for equality
				got[i].Conn = tt.want[i].Conn
				assert.Equal(t, tt.want[i], got[i])
			}
		})
	}
}

type ByName []Peer

func (n ByName) Len() int           { return len(n) }
func (n ByName) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n ByName) Less(i, j int) bool { return n[i].Name < n[j].Name }

type FakeClientConnBuilder struct {
	OnClientConn func(target string) (ClientConn, error)
}

func (b FakeClientConnBuilder) ClientConn(target string) (ClientConn, error) {
	if b.OnClientConn != nil {
		return b.OnClientConn(target)
	}
	panic("OnClientConn not set")
}

type FakeClientConn struct {
	OnGetState  func() connectivity.State
	OnClose     func() error
	OnInvoke    func(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error
	OnNewStream func(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error)
}

func (c FakeClientConn) GetState() connectivity.State {
	if c.OnGetState != nil {
		return c.OnGetState()
	}
	panic("OnGetState not set")
}

func (c FakeClientConn) Close() error {
	if c.OnClose != nil {
		return c.OnClose()
	}
	panic("OnClose not set")
}

func (c FakeClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	if c.OnInvoke != nil {
		return c.OnInvoke(ctx, method, args, reply, opts...)
	}
	panic("OnInvoke not set")
}

func (c FakeClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	if c.OnNewStream != nil {
		return c.OnNewStream(ctx, desc, method, opts...)
	}
	panic("OnNewStream not set")
}
