// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

func FakeSecretStore(secrets map[string][]byte) resource.Store[*slim_corev1.Secret] {
	store := newMockBGPCPResourceStore[*slim_corev1.Secret]()
	for k, v := range secrets {
		store.Upsert(&slim_corev1.Secret{
			ObjectMeta: slim_metav1.ObjectMeta{
				Namespace: "bgp-secrets",
				Name:      k,
			},
			Data: map[string]slim_corev1.Bytes{"password": slim_corev1.Bytes(v)},
		})
	}
	return store
}

// TestNeighborReconciler confirms the `neighborReconciler` function configures
// the desired BGP neighbors given a CiliumBGPVirtualRouter configuration.
func TestNeighborReconciler(t *testing.T) {
	type checkTimers struct {
		holdTimer         bool
		connectRetryTimer bool
		keepaliveTimer    bool
		grRestartTime     bool
	}

	table := []struct {
		// name of the test
		name string
		// existing neighbors, expanded to CiliumBGPNeighbor during test
		neighbors []v2alpha1api.CiliumBGPNeighbor
		// new neighbors to configure, expanded into CiliumBGPNeighbor.
		//
		// this is the resulting neighbors we expect on the BgpServer.
		newNeighbors []v2alpha1api.CiliumBGPNeighbor
		// secretStore passed to the test, provides a way to fetch secrets (use FakeSecretStore above).
		secretStore resource.Store[*slim_corev1.Secret]
		// checks validates set timer values
		checks checkTimers
		// expected secret if set.
		expectedSecret string
		// expected password if set.
		expectedPassword string
		// error provided or nil
		err error
	}{
		{
			name: "no change",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			err: nil,
		},
		{
			name: "neighbor with peer port",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(42424)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(42424)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			err: nil,
		},
		{
			name: "additional neighbor",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			err: nil,
		},
		{
			name: "remove neighbor",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			err: nil,
		},
		{
			name: "update neighbor",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", ConnectRetryTimeSeconds: pointer.Int32(120)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", ConnectRetryTimeSeconds: pointer.Int32(120)},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", ConnectRetryTimeSeconds: pointer.Int32(120)},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), ConnectRetryTimeSeconds: pointer.Int32(99)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), ConnectRetryTimeSeconds: pointer.Int32(120)},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), ConnectRetryTimeSeconds: pointer.Int32(120)},
			},
			checks: checkTimers{
				connectRetryTimer: true,
			},
			err: nil,
		},
		{
			name: "update neighbor - graceful restart",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: pointer.Int32(v2alpha1api.DefaultBGPGRRestartTimeSeconds),
				}},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: pointer.Int32(v2alpha1api.DefaultBGPGRRestartTimeSeconds),
				}},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: pointer.Int32(v2alpha1api.DefaultBGPGRRestartTimeSeconds),
				}},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
					Enabled:            false,
					RestartTimeSeconds: pointer.Int32(0),
				}},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: pointer.Int32(v2alpha1api.DefaultBGPGRRestartTimeSeconds),
				}},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), GracefulRestart: &v2alpha1api.CiliumBGPNeighborGracefulRestart{
					Enabled:            true,
					RestartTimeSeconds: pointer.Int32(v2alpha1api.DefaultBGPGRRestartTimeSeconds),
				}},
			},
			checks: checkTimers{
				grRestartTime: true,
			},
			err: nil,
		},
		{
			name: "update neighbor port",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(42424)},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			err: nil,
		},
		{
			name: "remove all neighbors",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.2/32"},
				{PeerASN: 64124, PeerAddress: "192.168.0.3/32"},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{},
			err:          nil,
		},
		{
			name:      "add neighbor with a password",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), AuthSecretRef: pointer.String("a-secret")},
			},
			secretStore:      FakeSecretStore(map[string][]byte{"a-secret": []byte("a-password")}),
			expectedSecret:   "a-secret",
			expectedPassword: "a-password",
			err:              nil,
		},
		{
			name: "neighbor's password secret not found",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), AuthSecretRef: pointer.String("bad-secret")},
			},
			secretStore: FakeSecretStore(map[string][]byte{}),
			err:         nil,
		},
		{
			name: "bad secret store, returns error",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort)},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), AuthSecretRef: pointer.String("a-secret")},
			},
			err: errors.New("fetch secret error"),
		},
		{
			name: "neighbor's secret updated",
			neighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), AuthSecretRef: pointer.String("a-secret")},
			},
			newNeighbors: []v2alpha1api.CiliumBGPNeighbor{
				{PeerASN: 64124, PeerAddress: "192.168.0.1/32", PeerPort: pointer.Int32(v2alpha1api.DefaultBGPPeerPort), AuthSecretRef: pointer.String("another-secret")},
			},
			secretStore:      FakeSecretStore(map[string][]byte{"another-secret": []byte("another-password")}),
			expectedSecret:   "another-secret",
			expectedPassword: "another-password",
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test BgpServer: %v", err)
			}
			t.Cleanup(func() {
				testSC.Server.Stop()
			})
			// create current vRouter config and add neighbors
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  64125,
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}
			for _, n := range tt.neighbors {
				n.SetDefaults()
				oldc.Neighbors = append(oldc.Neighbors, n)
				// create a temp. reconciler so we can get secrets.
				neighborReconciler := NewNeighborReconciler(tt.secretStore, &option.DaemonConfig{BGPSecretsNamespace: "bgp-secrets"}).Reconciler.(*NeighborReconciler)

				tcpPassword, err := neighborReconciler.fetchPeerPassword(testSC, &n)
				if err != nil {
					t.Fatalf("Failed to fetch peer password for oldc: %v", err)
				}
				if tcpPassword != "" {
					neighborReconciler.updatePeerPassword(testSC, &n, tcpPassword)
				}
				testSC.Server.AddNeighbor(context.Background(), types.NeighborRequest{
					Neighbor: &n,
					VR:       oldc,
					Password: tcpPassword,
				})
			}
			testSC.Config = oldc

			// create new virtual router config with desired neighbors
			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:  64125,
				Neighbors: []v2alpha1api.CiliumBGPNeighbor{},
			}
			newc.Neighbors = append(newc.Neighbors, tt.newNeighbors...)
			newc.SetDefaults()

			neighborReconciler := NewNeighborReconciler(tt.secretStore, &option.DaemonConfig{BGPSecretsNamespace: "bgp-secrets"}).Reconciler
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
			}

			err = neighborReconciler.Reconcile(context.Background(), params)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("want error: %v, got: %v", (tt.err == nil), err)
			}

			// clear out secret ref if one isn't expected
			if tt.expectedSecret == "" {
				for i := range tt.newNeighbors {
					tt.newNeighbors[i].AuthSecretRef = nil
				}
			}

			// check testSC for desired neighbors
			var getPeerResp types.GetPeerStateResponse
			getPeerResp, err = testSC.Server.GetPeerState(context.Background())
			if err != nil {
				t.Fatalf("failed creating test BgpServer: %v", err)
			}
			var runningPeers []v2alpha1api.CiliumBGPNeighbor

			for _, peer := range getPeerResp.Peers {
				toCiliumPeer := v2alpha1api.CiliumBGPNeighbor{
					PeerAddress: toHostPrefix(peer.PeerAddress),
					PeerPort:    pointer.Int32(int32(peer.PeerPort)),
					PeerASN:     peer.PeerAsn,
				}

				if tt.checks.holdTimer {
					toCiliumPeer.HoldTimeSeconds = pointer.Int32(int32(peer.ConfiguredHoldTimeSeconds))
				}

				if tt.checks.connectRetryTimer {
					toCiliumPeer.ConnectRetryTimeSeconds = pointer.Int32(int32(peer.ConnectRetryTimeSeconds))
				}

				if tt.checks.keepaliveTimer {
					toCiliumPeer.KeepAliveTimeSeconds = pointer.Int32(int32(peer.ConfiguredKeepAliveTimeSeconds))
				}

				if tt.checks.grRestartTime {
					toCiliumPeer.GracefulRestart = &v2alpha1api.CiliumBGPNeighborGracefulRestart{
						Enabled:            peer.GracefulRestart.Enabled,
						RestartTimeSeconds: pointer.Int32(int32(peer.GracefulRestart.RestartTimeSeconds)),
					}
				}

				// Check the API correctly reports a password was used.
				require.Equal(t, tt.expectedPassword != "", peer.TCPPasswordEnabled)
				if tt.expectedPassword != "" && peer.TCPPasswordEnabled {
					toCiliumPeer.AuthSecretRef = pointer.String(tt.expectedSecret)
				}

				runningPeers = append(runningPeers, toCiliumPeer)
			}

			require.ElementsMatch(t, tt.newNeighbors, runningPeers)
		})
	}
}

// hostPrefixLen returns addr/32 for ipv4 address and addr/128 for ipv6 address
func toHostPrefix(addr string) string {
	addrNet := netip.MustParseAddr(addr)
	bits := 32
	if addrNet.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addrNet, bits).String()
}
