// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
							once.Do(func() { close(done) })
							return connectivity.TransientFailure
						},
						OnClose: func() error {
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
					`level=warning msg="Failed to create gRPC client" address="192.0.1.1:4244" error="Don't feel like workin' today" hubble-tls=false next-try-in=1s peer=unreachable`,
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
				prometheus.NewPedanticRegistry(),
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

func TestPeerManager_PeerClientReconnect(t *testing.T) {
	type pcNot struct {
		not *peerpb.ChangeNotification
		err error
	}
	pcChan := make(chan pcNot)
	pcCloseCount := atomic.Int32{}
	pcDialCount := atomic.Int32{}
	pc := testutils.FakePeerClientBuilder{
		OnClient: func(_ string) (peerTypes.Client, error) {
			pcDialCount.Add(1)
			return &testutils.FakePeerClient{
				OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
					return &testutils.FakePeerNotifyClient{
						OnRecv: func() (*peerpb.ChangeNotification, error) {
							n := <-pcChan
							return n.not, n.err
						},
					}, nil
				},
				OnClose: func() error {
					pcCloseCount.Add(1)
					return nil
				},
			}, nil
		},
	}
	ccCloseCount := atomic.Int32{}
	ccDialCount := atomic.Int32{}
	cc := FakeClientConnBuilder{
		OnClientConn: func(target, hostname string) (poolTypes.ClientConn, error) {
			ccDialCount.Add(1)
			return testutils.FakeClientConn{
				OnGetState: func() connectivity.State {
					return connectivity.Ready
				},
				OnClose: func() error {
					ccCloseCount.Add(1)
					return nil
				},
			}, nil
		},
	}
	mgr, err := NewPeerManager(
		prometheus.NewPedanticRegistry(),
		WithPeerClientBuilder(pc),
		WithClientConnBuilder(cc),
		WithConnCheckInterval(100*time.Second),
		WithRetryTimeout(500*time.Millisecond),
	)
	assert.NoError(t, err)
	mgr.Start()
	pcChan <- pcNot{
		not: &peerpb.ChangeNotification{
			Name:    "foo",
			Address: "192.0.1.1",
			Type:    peerpb.ChangeNotificationType_PEER_ADDED,
		},
	}

	assert.Eventually(t, func() bool {
		peers := mgr.List()
		if len(peers) != 1 {
			return false
		}
		if peers[0].Conn == nil {
			return false
		}
		return true
	}, 20*time.Second, 10*time.Millisecond)
	peers := mgr.List()
	assert.Equal(t, "192.0.1.1:4244", peers[0].Address.String())

	assert.EqualValues(t, 1, pcDialCount.Load())
	pcChan <- pcNot{
		err: errors.New("connection failed"),
	}
	assert.Eventually(t, func() bool {
		return pcCloseCount.Load() == 1
	}, 20*time.Second, 10*time.Millisecond)
	assert.Eventually(t, func() bool {
		return pcDialCount.Load() == 2
	}, 20*time.Second, 10*time.Millisecond)

	pcChan <- pcNot{
		not: &peerpb.ChangeNotification{
			Name:    "foo",
			Address: "192.0.1.2",
			Type:    peerpb.ChangeNotificationType_PEER_ADDED,
		},
	}

	assert.Eventually(t, func() bool {
		peers := mgr.List()
		return len(peers) == 1 && peers[0].Address.String() == "192.0.1.2:4244"
	}, time.Second, 10*time.Millisecond)

	assert.Eventually(t, func() bool {
		return ccDialCount.Load() == 2
	}, time.Minute, 10*time.Millisecond, "reconnect to  new address")
	assert.Eventually(t, func() bool {
		return ccCloseCount.Load() == 1
	}, 20*time.Second, 10*time.Millisecond, "close old connection")

	close(pcChan)
	mgr.Stop()

}

func TestPeerManager_CheckMetrics(t *testing.T) {
	var done chan struct{}
	var once sync.Once

	tests := []struct {
		name       string
		pcBuilder  peerTypes.ClientBuilder
		ccBuilder  poolTypes.ClientConnBuilder
		wantStatus map[string]uint32
	}{
		{
			name: "7 peers with all possible non-nil connectivity states",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								cns := []*peerpb.ChangeNotification{
									{
										Name:    "peererino_uno",
										Address: "192.0.1.1",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "peererino_dos",
										Address: "192.0.1.2",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "peererino_tres",
										Address: "192.0.1.3",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "peererino_cuatro",
										Address: "192.0.1.4",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "peererino_cinco",
										Address: "192.0.1.5",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "peererino_seis",
										Address: "192.0.1.6",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "peererino_siete",
										Address: "192.0.1.7",
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
				OnClientConn: func() onClientConnFunc {
					var i int
					return func(target, hostname string) (poolTypes.ClientConn, error) {
						return testutils.FakeClientConn{
							OnGetState: func() connectivity.State {
								states := []connectivity.State{
									connectivity.Idle,
									connectivity.Ready,
									connectivity.Connecting,
									connectivity.TransientFailure,
									connectivity.Shutdown,
								}
								resultState := states[i%len(states)]
								i = (i + 1) % 7
								return resultState
							},
							OnClose: func() error {
								return nil
							},
						}, nil
					}
				}(),
			},
			wantStatus: map[string]uint32{
				"READY":             2,
				"CONNECTING":        1,
				"IDLE":              2,
				"TRANSIENT_FAILURE": 1,
				"SHUTDOWN":          1,
				"NIL_CONNECTION":    0,
			},
		},
		{
			name: "3 peers with nil connection",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(_ context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								cns := []*peerpb.ChangeNotification{
									{
										Name:    "noip_uno",
										Address: "",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "noip_dos",
										Address: "",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "noip_tres",
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
			wantStatus: map[string]uint32{
				"READY":             0,
				"CONNECTING":        0,
				"IDLE":              0,
				"TRANSIENT_FAILURE": 0,
				"SHUTDOWN":          0,
				"NIL_CONNECTION":    3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done = make(chan struct{})
			once = sync.Once{}

			var buf bytes.Buffer
			formatter := &logrus.TextFormatter{
				DisableColors:    true,
				DisableTimestamp: true,
			}
			logger := logrus.New()
			logger.SetOutput(&buf)
			logger.SetFormatter(formatter)
			logger.SetLevel(logrus.DebugLevel)

			registry := prometheus.NewPedanticRegistry()
			options := []Option{
				WithPeerClientBuilder(tt.pcBuilder),
				WithClientConnBuilder(tt.ccBuilder),
				WithLogger(logger),
				WithConnStatusInterval(2 * time.Second),
				// set interval large enough not to fire in 3 seconds sleep
				WithConnCheckInterval(20 * time.Minute),
			}

			mgr, err := NewPeerManager(registry, options...)
			assert.NoError(t, err)
			mgr.Start()
			wantExp := metricTextFormatFromPeerStatusMap(tt.wantStatus)
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				err = testutil.GatherAndCompare(registry, bytes.NewBufferString(wantExp), "hubble_relay_pool_peer_connection_status")
				assert.NoError(c, err)
			}, time.Minute, time.Second)
			<-done
			mgr.Stop()
		})
	}
}

func TestPeerManager_Status(t *testing.T) {

	tests := []struct {
		name               string
		pcBuilder          peerTypes.ClientBuilder
		ccBuilder          poolTypes.ClientConnBuilder
		wantPeerServiceOk  bool
		wantAvailablePeers int
	}{
		{
			name: "available peer API and 3 available peers with different states",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(ctx context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								cns := []*peerpb.ChangeNotification{
									{
										Name:    "foo",
										Address: "192.0.1.1",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "bar",
										Address: "192.0.1.2",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "buzz",
										Address: "192.0.1.3",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
								}
								return &testutils.FakePeerNotifyClient{
									OnRecv: func() (*peerpb.ChangeNotification, error) {
										i++
										switch {
										case i >= len(cns):
											<-ctx.Done()
											return nil, ctx.Err()
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
					i := -1
					return func(target, hostname string) (poolTypes.ClientConn, error) {
						i++
						return testutils.FakeClientConn{
							OnGetState: func() connectivity.State {
								states := []connectivity.State{
									connectivity.Idle,
									connectivity.Ready,
									connectivity.Connecting,
								}
								resultState := states[i]
								return resultState
							},
							OnClose: func() error {
								return nil
							},
						}, nil
					}
				}(),
			},
			wantAvailablePeers: 3,
			wantPeerServiceOk:  true,
		},
		{
			name: "available peer API and no available peers",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					i := -1
					return func(target string) (peerTypes.Client, error) {
						return &testutils.FakePeerClient{
							OnNotify: func(ctx context.Context, _ *peerpb.NotifyRequest, _ ...grpc.CallOption) (peerpb.Peer_NotifyClient, error) {
								cns := []*peerpb.ChangeNotification{
									{
										Name:    "foo",
										Address: "192.0.1.1",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "bar",
										Address: "192.0.1.2",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
									{
										Name:    "buzz",
										Address: "192.0.1.3",
										Type:    peerpb.ChangeNotificationType_PEER_ADDED,
									},
								}
								return &testutils.FakePeerNotifyClient{
									OnRecv: func() (*peerpb.ChangeNotification, error) {
										i++
										switch {
										case i >= len(cns):
											<-ctx.Done()
											return nil, ctx.Err()
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
					i := -1
					return func(target, hostname string) (poolTypes.ClientConn, error) {
						i++
						if i > 2 {
							return nil, nil
						}
						return testutils.FakeClientConn{
							OnGetState: func() connectivity.State {
								states := []connectivity.State{
									connectivity.Shutdown,
									connectivity.TransientFailure,
									connectivity.TransientFailure,
								}
								resultState := states[i]
								return resultState
							},
							OnClose: func() error {
								return nil
							},
						}, nil
					}
				}(),
			},
			wantAvailablePeers: 0,
			wantPeerServiceOk:  true,
		},
		{
			name: "available peer API and no available peers",
			pcBuilder: testutils.FakePeerClientBuilder{
				OnClient: func() onClientFunc {
					return func(target string) (peerTypes.Client, error) {
						return nil, errors.New("on PTO")
					}
				}(),
			},
			ccBuilder:          FakeClientConnBuilder{},
			wantAvailablePeers: 0,
			wantPeerServiceOk:  false,
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

			registry := prometheus.NewPedanticRegistry()
			options := []Option{
				WithPeerClientBuilder(tt.pcBuilder),
				WithClientConnBuilder(tt.ccBuilder),
				WithLogger(logger),
				WithConnStatusInterval(2 * time.Second),
				// set interval large enough not to fire in 3 seconds sleep
				WithConnCheckInterval(20 * time.Minute),
			}

			mgr, err := NewPeerManager(registry, options...)
			assert.NoError(t, err)
			mgr.Start()
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				stat := mgr.Status()
				assert.Equal(c, tt.wantPeerServiceOk, stat.PeerServiceConnected)
				assert.Equal(c, tt.wantAvailablePeers, stat.AvailablePeers)
			}, 10*time.Second, 200*time.Millisecond)
			mgr.Stop()
		})
	}
}

// metricTextFormatFromPeerStatusMap converts peer status map to the metric text format
// expected by Prometheus testutil library
func metricTextFormatFromPeerStatusMap(peerStatus map[string]uint32) string {
	var buf strings.Builder
	buf.WriteString(`# HELP hubble_relay_pool_peer_connection_status Measures the connectivity status of all peers by counting the number of peers for each given connection status.
# TYPE hubble_relay_pool_peer_connection_status gauge
`)
	keys := make([]string, 0, len(peerStatus))
	for key := range peerStatus {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		buf.WriteString(fmt.Sprintf("hubble_relay_pool_peer_connection_status{status=\"%s\"} %d\n", key, peerStatus[key]))
	}
	return buf.String()
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
