// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
)

func TestNodeAdd(t *testing.T) {
	tests := []struct {
		name        string
		withoutTLS  bool
		addressPref serviceoption.AddressFamilyPreference
		arg         types.Node
		want        *peerpb.ChangeNotification
	}{
		{
			name:       "node with just a name",
			withoutTLS: true,
			arg: types.Node{
				Name: "name",
			},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name:       "node with just a name and cluster",
			withoutTLS: true,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name:        "node with name, cluster and one internal IP address",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name:        "node with name, cluster and one external IP address",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name:        "node with name, cluster and mixed IP addresses preferring IPv4",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("fe80::1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name:        "node with name, cluster and mixed IP addresses preferring IPv6",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv6,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("fe80::1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "fe80::1",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
			},
		}, {
			name: "node with a name and withTLS is set",
			arg: types.Node{
				Name: "name",
			},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				Tls: &peerpb.TLS{
					ServerName: "name.default.hubble-grpc.cilium.io",
				},
			},
		}, {
			name: "node with name, cluster and withTLS is set",
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				Tls: &peerpb.TLS{
					ServerName: "name.cluster.hubble-grpc.cilium.io",
				},
			},
		}, {
			name: "node name with dots",
			arg: types.Node{
				Name:    "my.very.long.node.name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/my.very.long.node.name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				Tls: &peerpb.TLS{
					ServerName: "my-very-long-node-name.cluster.hubble-grpc.cilium.io",
				},
			},
		}, {
			name: "node name with dots in the cluster name section",
			arg: types.Node{
				Name:    "my.very.long.node.name",
				Cluster: "cluster.name.with.dots",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster.name.with.dots/my.very.long.node.name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				Tls: &peerpb.TLS{
					ServerName: "my-very-long-node-name.cluster-name-with-dots.hubble-grpc.cilium.io",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler(tt.withoutTLS, tt.addressPref)
			defer h.Close()

			var got *peerpb.ChangeNotification
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				got = <-h.C
				wg.Done()
			}()
			h.NodeAdd(tt.arg)
			wg.Wait()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNodeUpdate(t *testing.T) {
	type args struct {
		old, updated types.Node
	}
	tests := []struct {
		name        string
		withoutTLS  bool
		addressPref serviceoption.AddressFamilyPreference
		args        args
		want        []*peerpb.ChangeNotification
	}{
		{
			name:       "a node is renamed",
			withoutTLS: true,
			args: args{
				types.Node{
					Name: "old",
				}, types.Node{
					Name: "new",
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "old",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "new",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				},
			},
		}, {
			name:       "a node within a named cluster is renamed",
			withoutTLS: true,
			args: args{
				types.Node{
					Name:    "old",
					Cluster: "cluster",
				}, types.Node{
					Name:    "new",
					Cluster: "cluster",
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "cluster/old",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				}, {
					Name:    "cluster/new",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
				},
			},
		}, {
			name:        "a node with name, cluster and one internal IP address, the latter is updated",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			args: args{
				types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					},
				}, types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeInternalIP,
							IP:   net.ParseIP("192.0.2.2"),
						},
					}},
			},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "cluster/name",
					Address: "192.0.2.2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				},
			},
		}, {
			name:        "node with name, cluster and one external IP address, the latter is updated",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			args: args{
				types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					},
				}, types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.2"),
						},
					},
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "cluster/name",
					Address: "192.0.2.2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				},
			},
		}, {
			name:        "node with name, cluster and mixed IP addresses preferring IPv4, the latter is updated",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			args: args{
				types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					},
				}, types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.2"),
						},
						{
							Type: addressing.NodeInternalIP,
							IP:   net.ParseIP("fe80::2"),
						},
					},
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "cluster/name",
					Address: "192.0.2.2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				},
			},
		}, {
			name:        "node with name, cluster and mixed IP addresses preferring IPv6, the latter is updated",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv6,
			args: args{
				types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("fe80::1"),
						},
					},
				}, types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.2"),
						},
						{
							Type: addressing.NodeInternalIP,
							IP:   net.ParseIP("fe80::2"),
						},
					},
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "cluster/name",
					Address: "fe80::2",
					Type:    peerpb.ChangeNotificationType_PEER_UPDATED,
				},
			},
		}, {
			name:       "node with name, cluster and one external IP address, no name or address change",
			withoutTLS: true,
			args: args{
				types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					},
				}, types.Node{
					Name:    "name",
					Cluster: "cluster",
					IPAddresses: []types.Address{
						{
							Type: addressing.NodeExternalIP,
							IP:   net.ParseIP("192.0.2.1"),
						},
					},
				}},
			want: nil,
		}, {
			name: "a node is renamed and withTLS is set",
			args: args{
				types.Node{
					Name: "old",
				}, types.Node{
					Name: "new",
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "old",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "old.default.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "new",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "new.default.hubble-grpc.cilium.io",
					},
				},
			},
		}, {
			name: "a node within a named cluster is renamed and withTLS is set",
			args: args{
				types.Node{
					Name:    "old",
					Cluster: "cluster",
				}, types.Node{
					Name:    "new",
					Cluster: "cluster",
				}},
			want: []*peerpb.ChangeNotification{
				{
					Name:    "cluster/old",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_DELETED,
					Tls: &peerpb.TLS{
						ServerName: "old.cluster.hubble-grpc.cilium.io",
					},
				}, {
					Name:    "cluster/new",
					Address: "",
					Type:    peerpb.ChangeNotificationType_PEER_ADDED,
					Tls: &peerpb.TLS{
						ServerName: "new.cluster.hubble-grpc.cilium.io",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler(tt.withoutTLS, tt.addressPref)
			defer h.Close()

			var got []*peerpb.ChangeNotification
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				for i := 0; i < len(tt.want); i++ {
					got = append(got, <-h.C)
				}
				wg.Done()
			}()
			h.NodeUpdate(tt.args.old, tt.args.updated)
			wg.Wait()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNodeDelete(t *testing.T) {
	tests := []struct {
		name        string
		withoutTLS  bool
		addressPref serviceoption.AddressFamilyPreference
		arg         types.Node
		want        *peerpb.ChangeNotification
	}{
		{
			name:       "node with just a name",
			withoutTLS: true,
			arg: types.Node{
				Name: "name",
			},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name:       "node with just a name and cluster",
			withoutTLS: true,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name:        "node with name, cluster and one internal IP address",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name:        "node with name, cluster and one external IP address",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name:        "node with name, cluster and mixed IP addresses preferring IPv4",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv4,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("fe80::1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "192.0.2.1",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name:        "node with name, cluster and mixed IP addresses preferring IPv6",
			withoutTLS:  true,
			addressPref: serviceoption.AddressPreferIPv6,
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
				IPAddresses: []types.Address{
					{
						Type: addressing.NodeExternalIP,
						IP:   net.ParseIP("192.0.2.1"),
					},
					{
						Type: addressing.NodeInternalIP,
						IP:   net.ParseIP("fe80::1"),
					},
				},
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "fe80::1",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
			},
		}, {
			name: "node with a name and withTLS is set",
			arg: types.Node{
				Name: "name",
			},
			want: &peerpb.ChangeNotification{
				Name:    "name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				Tls: &peerpb.TLS{
					ServerName: "name.default.hubble-grpc.cilium.io",
				},
			},
		}, {
			name: "node with a name and cluster and withTLS is set",
			arg: types.Node{
				Name:    "name",
				Cluster: "cluster",
			},
			want: &peerpb.ChangeNotification{
				Name:    "cluster/name",
				Address: "",
				Type:    peerpb.ChangeNotificationType_PEER_DELETED,
				Tls: &peerpb.TLS{
					ServerName: "name.cluster.hubble-grpc.cilium.io",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandler(tt.withoutTLS, tt.addressPref)
			defer h.Close()

			var got *peerpb.ChangeNotification
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				got = <-h.C
				wg.Done()
			}()
			h.NodeDelete(tt.arg)
			wg.Wait()
			assert.Equal(t, tt.want, got)
		})
	}
}
