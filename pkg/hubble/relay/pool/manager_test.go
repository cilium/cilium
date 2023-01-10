// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
)

type onClientFunc = func(string) (peerTypes.Client, error)
type onClientConnFunc = func(string, string) (poolTypes.ClientConn, error)

func TestPeerManager(t *testing.T) {
	// both variables are re-initialized for each test
	var done chan struct{}
	var once sync.Once

	type want struct {
		peers []poolTypes.Peer
		log   []string
	}
	tests := []struct {
		name      string
		pcBuilder peerTypes.ClientBuilder
		ccBuilder poolTypes.ClientConnBuilder
		want      want
	}{
		{
			name: "empty pool",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									once.Do(func() { close(done) })
									return nil, io.EOF
								},
							}, nil
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
		}, {
			name: "1 peer without IP address",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								cns := []*peerpb.ChangeNotification{
									{
										Name:    "noip",
										Address: "",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
								}
								return &testutils.FakePeerNotifyClient{
									OnRecv: func() (*peerpb.ChangeNotification, error) {
										i++
										switch {
										case i >= len(cns):
											once.Do(func() { close(done) })
											return nil, io.EOF
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name:    "noip",
							Address: nil,
						},
						Conn: nil,
					},
				},
			},
		}, {
			name: "1 unreachable peer",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
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
											once.Do(func() { close(done) })
											return nil, io.EOF
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					return nil, io.EOF
				},
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "unreachable",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.1.1"),
								Port: defaults.ServerPort,
							},
						},
						Conn: nil,
					},
				},
			},
		}, {
			name: "1 reachable peer",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
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
											return nil, io.EOF
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					return testutils.FakeClientConn{
						OnGetState: func() connectivity.State {
							once.Do(func() { close(done) })
							return connectivity.Ready
						},
					}, nil
				},
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "reachable",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.1.1"),
								Port: defaults.ServerPort,
							},
						},
						Conn: testutils.FakeClientConn{},
					},
				},
			},
		}, {
			name: "1 peer is deleted",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
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
											return nil, io.EOF
										case i == len(cns)-1:
											close(done)
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					return testutils.FakeClientConn{
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
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
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
											return nil, io.EOF
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					return testutils.FakeClientConn{
						OnGetState: func() connectivity.State {
							return connectivity.TransientFailure
						},
						OnClose: func() error {
							once.Do(func() { close(done) })
							return nil
						},
					}, nil
				},
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "unreachable",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.1.1"),
								Port: defaults.ServerPort,
							},
						},
						Conn: testutils.FakeClientConn{},
					},
				},
			},
		}, {
			name: "1 peer added then modified",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
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
											return nil, io.EOF
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func() onClientConnFunc {
					var i int
					return func(target, hostname string) (poolTypes.ClientConn, error) {
						return testutils.FakeClientConn{
							OnGetState: func() connectivity.State {
								i++
								if i == 2 {
									close(done)
								}
								return connectivity.Ready
							},
							OnClose: func() error {
								return nil
							},
						}, nil
					}
				}(),
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "reachable",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.5.5"),
								Port: defaults.ServerPort,
							},
						},
						Conn: testutils.FakeClientConn{},
					},
				},
			},
		}, {
			name: "2 peers added, 1 deleted",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
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
											return nil, io.EOF
										case i == len(cns)-1:
											close(done)
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					return nil, nil
				},
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "two",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.1.2"),
								Port: defaults.ServerPort,
							},
						},
						Conn: nil,
					},
				},
			},
		}, {
			name: "2 peers added, 1 deleted, TLS enabled",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								cns := []*peerpb.ChangeNotification{
									{
										Name:    "one",
										Address: "192.0.1.1",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
										Tls: &peerpb.TLS{
											ServerName: "one.default.hubble-grpc.cilium.io",
										},
									}, {
										Name:    "two",
										Address: "192.0.1.2",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
										Tls: &peerpb.TLS{
											ServerName: "two.default.hubble-grpc.cilium.io",
										},
									}, {
										Name:    "one",
										Address: "192.0.1.1",
										Type:    peerpb.ChangeNotificationType_PEER_DELETED,
										Tls: &peerpb.TLS{
											ServerName: "one.default.hubble-grpc.cilium.io",
										},
									},
								}
								return &testutils.FakePeerNotifyClient{
									OnRecv: func() (*peerpb.ChangeNotification, error) {
										i++
										switch {
										case i >= len(cns):
											return nil, io.EOF
										case i == len(cns)-1:
											close(done)
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					return nil, nil
				},
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "two",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.1.2"),
								Port: defaults.ServerPort,
							},
							TLSEnabled:    true,
							TLSServerName: "two.default.hubble-grpc.cilium.io",
						},
						Conn: nil,
					},
				},
			},
		}, {
			name: "PeerClientBuilder errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					once.Do(func() { close(done) })
					return nil, errors.New("I'm on PTO")
				},
			},
			want: want{
				log: []string{
					`level=warning msg="Failed to create peer client for peers synchronization; will try again after the timeout has expired" error="I'm on PTO" target="unix:///var/run/cilium/hubble.sock"`,
				},
			},
		}, {
			name: "ClientConnBuilder errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					var i int
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								return &testutils.FakePeerNotifyClient{
									OnRecv: func() (*peerpb.ChangeNotification, error) {
										i++
										if i > 1 {
											return nil, io.EOF
										}
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
					}
				}(),
			},
			ccBuilder: FakeClientConnBuilder{
				OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
					once.Do(func() { close(done) })
					return nil, errors.New("Don't feel like workin' today")
				},
			},
			want: want{
				peers: []poolTypes.Peer{
					{
						Peer: peerTypes.Peer{
							Name: "unreachable",
							Address: &net.TCPAddr{
								IP:   net.ParseIP("192.0.1.1"),
								Port: defaults.ServerPort,
							},
						},
						Conn: nil,
					},
				},
				log: []string{
					`level=warning msg="Failed to create gRPC client" address="192.0.1.1:4244" error="Don't feel like workin' today" hubble-tls=false next-try-in=10s peer=unreachable`,
				},
			},
		}, {
			name: "peer notify errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							once.Do(func() { close(done) })
							return nil, errors.New("Don't feel like workin' today")
						},
						OnClose: func() error {
							return nil
						},
					}, nil
				},
			},
			want: want{
				log: []string{
					`level=warning msg="Failed to create peer notify client for peers change notification; will try again after the timeout has expired" connection timeout=30s error="Don't feel like workin' today"`,
				},
			},
		}, {
			name: "peer recv errors out",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func(target string) (peerTypes.Client, error) {
					return &testutils.FakePeerClient{
						OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
							return &testutils.FakePeerNotifyClient{
								OnRecv: func() (*peerpb.ChangeNotification, error) {
									once.Do(func() { close(done) })
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
			want: want{
				log: []string{`level=warning msg="Error while receiving peer change notification; will try again after the timeout has expired" connection timeout=30s error="Nope, ain't doin' nothin'`},
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

			done = make(chan struct{})
			once = sync.Once{}

			mgr, err := NewPeerManager(
				WithPeerClientBuilder(tt.pcBuilder),
				WithClientConnBuilder(tt.ccBuilder),
				WithConnCheckInterval(1*time.Second),
				WithLogger(logger),
			)
			assert.NoError(t, err)
			mgr.Start()
			<-done
			mgr.Stop()
			got := mgr.List()
			// the objects are not easily compared -> hack the assertion
			sort.Sort(ByName(got))
			sort.Sort(ByName(tt.want.peers))
			assert.Equal(t, len(tt.want.peers), len(got))
			for i := range got {
				if tt.want.peers[i].Conn == nil {
					assert.Nil(t, got[i].Conn)
				}
				// we only care whether this field is <nil> or not (tested above)
				// as this field is not easily compared, hack it so that we can
				// still assert the rest of the struct for equality
				got[i].Conn = tt.want.peers[i].Conn
				assert.Equal(t, tt.want.peers[i], got[i])
			}
			out := buf.String()
			for _, msg := range tt.want.log {
				assert.Contains(t, out, msg)
			}
		})
	}
}

type ByName []poolTypes.Peer

func (n ByName) Len() int           { return len(n) }
func (n ByName) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }
func (n ByName) Less(i, j int) bool { return n[i].Name < n[j].Name }

type FakeClientConnBuilder struct {
	OnClientConn func(target, hostname string) (poolTypes.ClientConn, error)
}

func (b FakeClientConnBuilder) ClientConn(target, hostname string) (poolTypes.ClientConn, error) {
	if b.OnClientConn != nil {
		return b.OnClientConn(target, hostname)
	}
	panic("OnClientConn not set")
}
