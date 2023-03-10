// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/node/types"
)

func TestService_Notify(t *testing.T) {
	type args struct {
		init   []types.Node
		add    []types.Node
		update []types.Node
		del    []types.Node
	}
	tests := []struct {
		name       string
		svcOptions []serviceoption.Option
		args       args
		want       []*peerpb.ChangeNotification
	}{
		{
			name:       "add 4 nodes with TLS info disabled",
			svcOptions: []serviceoption.Option{serviceoption.WithoutTLSInfo()},
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					},
				},
				add: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				},
			},
		}, {
			name:       "delete 3 nodes with TLS info disabled",
			svcOptions: []serviceoption.Option{serviceoption.WithoutTLSInfo()},
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
				del: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				},
			},
		}, {
			name:       "update 2 nodes with TLS info disabled",
			svcOptions: []serviceoption.Option{serviceoption.WithoutTLSInfo()},
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
				update: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.2")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::65")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				}, {
					Name:    "two",
					Address: "2001:db8::65",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				},
			},
		}, {
			name:       "rename 2 nodes with TLS info disabled",
			svcOptions: []serviceoption.Option{serviceoption.WithoutTLSInfo()},
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
				update: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "1",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name: "2",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "1",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "2",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				},
			},
		}, {
			name: "add 4 nodes",
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					},
				},
				add: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "zero.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "one.test.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "two.test.hubble-grpc.cilium.io",
					},
				},
			},
		}, {
			name: "delete 3 nodes",
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
				del: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name:    "one",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
						},
					}, {
						Name:    "two",
						Cluster: "test",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "zero.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "one.test.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "two.test.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "test/one",
					Address: "10.0.10.5",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "one.test.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "test/two",
					Address: "10.0.10.6",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "two.test.hubble-grpc.cilium.io",
					},
				},
			},
		}, {
			name: "update 2 nodes",
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
				update: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.2")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::65")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "zero.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::65",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				},
			},
		}, {
			name: "rename 2 nodes",
			args: args{
				init: []types.Node{
					{
						Name: "zero",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.1.1")},
						},
					}, {
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
				update: []types.Node{
					{
						Name: "one",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "1",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
						},
					}, {
						Name: "two",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					}, {
						Name: "2",
						IPAddresses: []types.Address{
							{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
						},
					},
				},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "zero",
					Address: "192.0.1.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "zero.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "one",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "one.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "1",
					Address: "192.0.2.1",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "1.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "two",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "two.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "2",
					Address: "2001:db8::68",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "2.default.hubble-grpc.cilium.io",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []*peerpb.ChangeNotification
			var wg sync.WaitGroup
			fakeServer := &testutils.FakePeerNotifyServer{
				OnSend: func(resp *peerpb.ChangeNotification) error {
					got = append(got, resp)
					wg.Done()
					return nil
				},
			}
			ready := make(chan struct{})
			cb := func(nh datapath.NodeHandler) {
				ready <- struct{}{}
			}
			notif := newNotifier(cb, tt.args.init)
			wg.Add(len(tt.args.init))
			svc := NewService(notif, tt.svcOptions...)
			done := make(chan struct{})
			go func() {
				err := svc.Notify(&peerpb.NotifyRequest{}, fakeServer)
				assert.NoError(t, err)
				close(done)
			}()
			<-ready
			for _, n := range tt.args.add {
				wg.Add(1)
				notif.notifyAdd(n)
			}
			for _, n := range tt.args.del {
				wg.Add(1)
				notif.notifyDelete(n)
			}
			// the update slice shall always be even with odd entry
			// corresponding to the old node and following even entries to the
			// updated one
			var o types.Node
			for i, n := range tt.args.update {
				if i%2 == 0 {
					n := n
					o = n
					continue
				}
				// the number of notifications we expect depends on the change
				// - identical: no notification
				// - name change: 2 notifications
				// - other change: 1 notification
				switch {
				case cmp.Diff(o, n) == "":
					// no-op
				case o.Name != n.Name:
					wg.Add(2)
				default:
					wg.Add(1)
				}
				notif.notifyUpdate(o, n)
			}
			wg.Wait()
			svc.Close()
			assert.Equal(t, tt.want, got)
			// wait for the notify call routine to finish
			<-done
		})
	}
}

func TestService_NotifyWithBlockedSend(t *testing.T) {
	fakeServer := &testutils.FakePeerNotifyServer{
		OnSend: func(resp *peerpb.ChangeNotification) error {
			<-time.After(100 * time.Millisecond)
			return nil
		},
	}
	ready := make(chan struct{})
	cb := func(nh datapath.NodeHandler) {
		ready <- struct{}{}
	}
	init := []types.Node{
		{
			Name: "one",
			IPAddresses: []types.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
			},
		}, {
			Name: "two",
			IPAddresses: []types.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("2001:db8::68")},
			},
		}, {
			Name:    "one",
			Cluster: "test",
			IPAddresses: []types.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.5")},
			},
		}, {
			Name:    "two",
			Cluster: "test",
			IPAddresses: []types.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.10.6")},
			},
		},
	}
	notif := newNotifier(cb, init)
	svc := NewService(notif, serviceoption.WithMaxSendBufferSize(2), serviceoption.WithoutTLSInfo())
	done := make(chan struct{})
	go func() {
		err := svc.Notify(&peerpb.NotifyRequest{}, fakeServer)
		assert.Equal(t, ErrStreamSendBlocked, err)
		close(done)
	}()
	<-ready
	for _, n := range init {
		notif.notifyAdd(n)
	}
	svc.Close()
	// wait for the notify call routine to finish
	<-done
}

type notifier struct {
	nodes       []types.Node
	subscribers map[datapath.NodeHandler]struct{}
	cb          func(nh datapath.NodeHandler)
	mu          lock.Mutex
}

var _ manager.Notifier = (*notifier)(nil)

func newNotifier(subCallback func(nh datapath.NodeHandler), nodes []types.Node) *notifier {
	return &notifier{
		nodes:       nodes,
		subscribers: make(map[datapath.NodeHandler]struct{}),
		cb:          subCallback,
	}
}

func (n *notifier) Subscribe(nh datapath.NodeHandler) {
	n.mu.Lock()
	n.subscribers[nh] = struct{}{}
	n.mu.Unlock()
	for _, e := range n.nodes {
		nh.NodeAdd(e)
	}
	if n.cb != nil {
		n.cb(nh)
	}
}

func (n *notifier) Unsubscribe(nh datapath.NodeHandler) {
	n.mu.Lock()
	delete(n.subscribers, nh)
	n.mu.Unlock()
}

func (n *notifier) notifyAdd(e types.Node) {
	n.mu.Lock()
	for s := range n.subscribers {
		s.NodeAdd(e)
	}
	n.mu.Unlock()
}

func (n *notifier) notifyDelete(e types.Node) {
	n.mu.Lock()
	for s := range n.subscribers {
		s.NodeDelete(e)
	}
	n.mu.Unlock()
}

func (n *notifier) notifyUpdate(o, e types.Node) {
	n.mu.Lock()
	for s := range n.subscribers {
		s.NodeUpdate(o, e)
	}
	n.mu.Unlock()
}
