// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	ipamtypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

// We use similar local listen ports as the tests in the pkg/bgpv1/test package.
// It is important to NOT use ports from the /proc/sys/net/ipv4/ip_local_port_range
// (defaulted to 32768-60999 on most Linux distributions) to avoid collisions with
// the ephemeral (source) ports. As this range is configurable, ideally, we should
// use the IANA-assigned ports below 1024 (e.g. 179) or mock GoBGP in these tests.
// See https://github.com/cilium/cilium/issues/26209 for more info.
const (
	localListenPort  = 1793
	localListenPort2 = 1794
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

// TestPreflightReconciler ensures if a BgpServer must be recreated, due to
// permanent configuration of the said server changing, its done so correctly.
func TestPreflightReconciler(t *testing.T) {
	var table = []struct {
		// name of test
		name string
		// routerID of original server
		routerID string
		// routerID to reconcile
		newRouterID string
		// local listen port of original server
		localPort int32
		// local listen port to reconcile
		newLocalPort int32
		// virtual router configuration to reconcile, used mostly for pointer
		// comparison
		config *v2alpha1api.CiliumBGPVirtualRouter
		// should a recreation of the BgpServer
		shouldRecreate bool
		// export a nil error or not
		err error
	}{
		{
			name:           "no change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.1",
			localPort:      localListenPort,
			newLocalPort:   localListenPort,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: false,
			err:            nil,
		},
		{
			name:           "router-id change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.2",
			localPort:      localListenPort,
			newLocalPort:   localListenPort,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:           "local-port change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.1",
			localPort:      localListenPort,
			newLocalPort:   localListenPort2,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
		{
			name:           "local-port, router-id change",
			routerID:       "192.168.0.1",
			newRouterID:    "192.168.0.2",
			localPort:      localListenPort,
			newLocalPort:   localListenPort2,
			config:         &v2alpha1api.CiliumBGPVirtualRouter{},
			shouldRecreate: true,
			err:            nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// our test BgpServer with our original router ID and local port
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   tt.routerID,
					ListenPort: tt.localPort,
				},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test BgpServer: %v", err)
			}

			// keep a pointer to the original server to avoid gc and to check
			// later
			originalServer := testSC.Server
			t.Cleanup(func() {
				originalServer.Stop() // stop our test server
				testSC.Server.Stop()  // stop any recreated server
			})

			// attach original config
			testSC.Config = tt.config
			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN: 64125,
			}

			preflightReconciler := NewPreflightReconciler().Reconciler
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "Test Node",
						Annotations: map[string]string{
							"cilium.io/bgp-virtual-router.64125": fmt.Sprintf("router-id=%s,local-port=%d", tt.newRouterID, tt.newLocalPort),
						},
					},
				},
			}

			err = preflightReconciler.Reconcile(context.Background(), params)
			if (tt.err == nil) != (err == nil) {
				t.Fatalf("wanted error: %v", (tt.err == nil))
			}
			if tt.shouldRecreate && testSC.Server == originalServer {
				t.Fatalf("preflightReconciler did not recreate server")
			}
			getBgpResp, err := testSC.Server.GetBGP(context.Background())
			if err != nil {
				t.Fatalf("failed to retrieve BGP Info for BgpServer under test: %v", err)
			}
			bgpInfo := getBgpResp.Global
			if bgpInfo.RouterID != tt.newRouterID {
				t.Fatalf("got: %v, want: %v", bgpInfo.RouterID, tt.newRouterID)
			}
			if bgpInfo.ListenPort != int32(tt.newLocalPort) {
				t.Fatalf("got: %v, want: %v", bgpInfo.ListenPort, tt.newLocalPort)
			}
		})
	}
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

func TestExportPodCIDRReconciler(t *testing.T) {
	var table = []struct {
		// name of the test case
		name string
		// whether ExportPodCIDR is enabled at start of test
		enabled bool
		// whether ExportPodCIDR should be enabled before reconciliation
		shouldEnable bool
		// the advertised PodCIDR blocks the test begins with, these are encoded
		// into Golang structs for the convenience of passing directly to the
		// ServerWithConfig.AdvertisePath() method.
		advertised []netip.Prefix
		// the updated PodCIDR blocks to reconcile.
		updated []string
		// error nil or not
		err error
	}{
		{
			name:         "disable",
			enabled:      true,
			shouldEnable: false,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
		},
		{
			name:         "enable",
			enabled:      false,
			shouldEnable: true,
			updated:      []string{"192.168.0.0/24"},
		},
		{
			name:         "no change",
			enabled:      true,
			shouldEnable: true,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			updated: []string{"192.168.0.0/24"},
		},
		{
			name:         "additional network",
			enabled:      true,
			shouldEnable: true,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			updated: []string{"192.168.0.0/24", "192.168.1.0/24"},
		},
		{
			name:         "removal of both networks",
			enabled:      true,
			shouldEnable: true,
			advertised: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
			updated: []string{},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// setup our test server, create a BgpServer, advertise the tt.advertised
			// networks, and store each returned Advertisement in testSC.PodCIDRAnnouncements
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: pointer.Bool(tt.enabled),
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc
			reconciler := NewExportPodCIDRReconciler().Reconciler.(*ExportPodCIDRReconciler)
			podCIDRAnnouncements := reconciler.getMetadata(testSC)
			for _, cidr := range tt.advertised {
				advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
					Path: types.NewPathForPrefix(cidr),
				})
				if err != nil {
					t.Fatalf("failed to advertise initial pod cidr routes: %v", err)
				}
				podCIDRAnnouncements = append(podCIDRAnnouncements, advrtResp.Path)
			}
			reconciler.storeMetadata(testSC, podCIDRAnnouncements)

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:      64125,
				ExportPodCIDR: pointer.Bool(tt.shouldEnable),
				Neighbors:     []v2alpha1api.CiliumBGPNeighbor{},
			}

			exportPodCIDRReconciler := NewExportPodCIDRReconciler().Reconciler
			params := ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "Test Node",
					},
					Spec: v2api.NodeSpec{
						IPAM: ipamtypes.IPAMSpec{
							PodCIDRs: tt.updated,
						},
					},
				},
			}

			// run the reconciler
			err = exportPodCIDRReconciler.Reconcile(context.Background(), params)
			if err != nil {
				t.Fatalf("failed to reconcile new pod cidr advertisements: %v", err)
			}
			podCIDRAnnouncements = reconciler.getMetadata(testSC)

			// if we disable exports of pod cidr ensure no advertisements are
			// still present.
			if tt.shouldEnable == false {
				if len(podCIDRAnnouncements) > 0 {
					t.Fatal("disabled export but advertisements till present")
				}
			}

			log.Printf("%+v %+v", podCIDRAnnouncements, tt.updated)

			// ensure we see tt.updated in testSC.PodCIDRAnnoucements
			for _, cidr := range tt.updated {
				prefix := netip.MustParsePrefix(cidr)
				var seen bool
				for _, advrt := range podCIDRAnnouncements {
					if advrt.NLRI.String() == prefix.String() {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("failed to advertise %v", cidr)
				}
			}

			// ensure testSC.PodCIDRAnnouncements does not contain advertisements
			// not in tt.updated
			for _, advrt := range podCIDRAnnouncements {
				var seen bool
				for _, cidr := range tt.updated {
					if advrt.NLRI.String() == cidr {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("unwanted advert %+v", advrt)
				}
			}

		})
	}
}

func TestLBServiceReconciler(t *testing.T) {
	blueSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
	redSelector := slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "red"}}
	svc1Name := resource.Key{Name: "svc-1", Namespace: "default"}
	svc1NonDefaultName := resource.Key{Name: "svc-1", Namespace: "non-default"}
	svc2NonDefaultName := resource.Key{Name: "svc-2", Namespace: "non-default"}
	ingressV4 := "192.168.0.1"
	ingressV4_2 := "192.168.0.2"
	ingressV4Prefix := ingressV4 + "/32"
	ingressV4Prefix_2 := ingressV4_2 + "/32"
	ingressV6 := "fd00:192:168::1"
	ingressV6Prefix := ingressV6 + "/128"

	svc1 := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      svc1Name.Name,
			Namespace: svc1Name.Namespace,
			Labels:    blueSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4,
					},
				},
			},
		},
	}

	svc1TwoIngress := svc1.DeepCopy()
	svc1TwoIngress.Status.LoadBalancer.Ingress =
		append(svc1TwoIngress.Status.LoadBalancer.Ingress,
			slim_corev1.LoadBalancerIngress{IP: ingressV6})

	svc1RedLabel := svc1.DeepCopy()
	svc1RedLabel.ObjectMeta.Labels = redSelector.MatchLabels

	svc1NonDefault := svc1.DeepCopy()
	svc1NonDefault.Namespace = svc1NonDefaultName.Namespace
	svc1NonDefault.Status.LoadBalancer.Ingress[0] = slim_corev1.LoadBalancerIngress{IP: ingressV4_2}

	svc1NonLB := svc1.DeepCopy()
	svc1NonLB.Spec.Type = slim_corev1.ServiceTypeClusterIP

	svc1ETPLocal := svc1.DeepCopy()
	svc1ETPLocal.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyLocal

	svc1ETPLocalTwoIngress := svc1TwoIngress.DeepCopy()
	svc1ETPLocalTwoIngress.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyLocal

	svc1IPv6ETPLocal := svc1.DeepCopy()
	svc1IPv6ETPLocal.Status.LoadBalancer.Ingress[0] = slim_corev1.LoadBalancerIngress{IP: ingressV6}
	svc1IPv6ETPLocal.Spec.ExternalTrafficPolicy = slim_corev1.ServiceExternalTrafficPolicyLocal

	svc1LbClass := svc1.DeepCopy()
	svc1LbClass.Spec.LoadBalancerClass = pointer.String(v2alpha1api.BGPLoadBalancerClass)

	svc1UnsupportedClass := svc1LbClass.DeepCopy()
	svc1UnsupportedClass.Spec.LoadBalancerClass = pointer.String("io.vendor/unsupported-class")

	svc2NonDefault := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      svc2NonDefaultName.Name,
			Namespace: svc2NonDefaultName.Namespace,
			Labels:    blueSelector.MatchLabels,
		},
		Spec: slim_corev1.ServiceSpec{
			Type: slim_corev1.ServiceTypeLoadBalancer,
		},
		Status: slim_corev1.ServiceStatus{
			LoadBalancer: slim_corev1.LoadBalancerStatus{
				Ingress: []slim_corev1.LoadBalancerIngress{
					{
						IP: ingressV4_2,
					},
				},
			},
		},
	}

	eps1IPv4Local := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
		},
	}

	eps1IPv4Remote := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
		},
	}

	eps1IPv4Mixed := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("10.0.0.1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("10.0.0.2"): {
				NodeName: "node2",
			},
		},
	}

	eps1IPv6Local := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv6",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv6",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("fd00:10::1"): {
				NodeName: "node1",
			},
		},
	}

	eps1IPv6Remote := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv6",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv6",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("fd00:10::2"): {
				NodeName: "node2",
			},
		},
	}

	eps1IPv6Mixed := &k8s.Endpoints{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "svc-1-ipv4",
			Namespace: "default",
		},
		EndpointSliceID: k8s.EndpointSliceID{
			ServiceID: k8s.ServiceID{
				Name:      "svc-1",
				Namespace: "default",
			},
			EndpointSliceName: "svc-1-ipv4",
		},
		Backends: map[cmtypes.AddrCluster]*k8s.Backend{
			cmtypes.MustParseAddrCluster("fd00:10::1"): {
				NodeName: "node1",
			},
			cmtypes.MustParseAddrCluster("fd00:10::2"): {
				NodeName: "node2",
			},
		},
	}

	var table = []struct {
		// name of the test case
		name string
		// The service selector of the vRouter
		oldServiceSelector *slim_metav1.LabelSelector
		// The service selector of the vRouter
		newServiceSelector *slim_metav1.LabelSelector
		// the advertised PodCIDR blocks the test begins with
		advertised map[resource.Key][]string
		// the services which will be "upserted" in the diffstore
		upsertedServices []*slim_corev1.Service
		// the services which will be "deleted" in the diffstore
		deletedServices []resource.Key
		// the endpoints which will be "upserted" in the diffstore
		upsertedEndpoints []*k8s.Endpoints
		// the updated PodCIDR blocks to reconcile, these are string encoded
		// for the convenience of attaching directly to the NodeSpec.PodCIDRs
		// field.
		updated map[resource.Key][]string
		// error nil or not
		err error
	}{
		// Add 1 ingress
		{
			name:               "lb-svc-1-ingress",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         make(map[resource.Key][]string),
			upsertedServices:   []*slim_corev1.Service{svc1},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// Add 2 ingress
		{
			name:               "lb-svc-2-ingress",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         make(map[resource.Key][]string),
			upsertedServices:   []*slim_corev1.Service{svc1TwoIngress},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		// Delete service
		{
			name:               "delete-svc",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			deletedServices: []resource.Key{
				svc1Name,
			},
			updated: map[resource.Key][]string{},
		},
		// Update service to no longer match
		{
			name:               "update-service-no-match",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			upsertedServices: []*slim_corev1.Service{svc1RedLabel},
			updated:          map[resource.Key][]string{},
		},
		// Update vRouter to no longer match
		{
			name:               "update-vrouter-selector",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &redSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			upsertedServices: []*slim_corev1.Service{svc1},
			updated:          map[resource.Key][]string{},
		},
		// 1 -> 2 ingress
		{
			name:               "update-1-to-2-ingress",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
			upsertedServices: []*slim_corev1.Service{svc1TwoIngress},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		// No selector
		{
			name:               "no-selector",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1},
			updated:            map[resource.Key][]string{},
		},
		// Namespace selector
		{
			name:               "svc-namespace-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.namespace": "default"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.namespace": "default"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				svc1,
				svc2NonDefault,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// Service name selector
		{
			name:               "svc-name-selector",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-1"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-1"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices: []*slim_corev1.Service{
				svc1,
				svc1NonDefault,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
				svc1NonDefaultName: {
					ingressV4Prefix_2,
				},
			},
		},
		// BGP load balancer class with matching selectors for service.
		{
			name:               "lb-class-and-selectors",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1LbClass},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// BGP load balancer class with no selectors for service.
		{
			name:               "lb-class-no-selectors",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1LbClass},
			updated:            map[resource.Key][]string{},
		},
		// BGP load balancer class with selectors for a different service.
		{
			name:               "lb-class-with-diff-selectors",
			oldServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-2"}},
			newServiceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"io.kubernetes.service.name": "svc-2"}},
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1LbClass},
			updated:            map[resource.Key][]string{},
		},
		// Unsupported load balancer class with matching selectors for service.
		{
			name:               "unsupported-lb-class-with-selectors",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1UnsupportedClass},
			updated:            map[resource.Key][]string{},
		},
		// Unsupported load balancer class with no matching selectors for service.
		{
			name:               "unsupported-lb-class-with-no-selectors",
			oldServiceSelector: nil,
			newServiceSelector: nil,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1UnsupportedClass},
			updated:            map[resource.Key][]string{},
		},
		// No-LB service
		{
			name:               "non-lb svc",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1NonLB},
			updated:            map[resource.Key][]string{},
		},
		// Service without endpoints
		{
			name:               "etp-local-no-endpoints",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{},
			updated:            map[resource.Key][]string{},
		},
		// externalTrafficPolicy=Local && IPv4 && single slice && local endpoint
		{
			name:               "etp-local-ipv4-single-slice-local",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv4Local},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && IPv4 && single slice && remote endpoint
		{
			name:               "etp-local-ipv4-single-slice-remote",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv4Remote},
			updated:            map[resource.Key][]string{},
		},
		// externalTrafficPolicy=Local && IPv4 && single slice && mixed endpoint
		{
			name:               "etp-local-ipv4-single-slice-mixed",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv4Mixed},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && IPv6 && single slice && local endpoint
		{
			name:               "etp-local-ipv6-single-slice-local",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1IPv6ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv6Local},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV6Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && IPv6 && single slice && remote endpoint
		{
			name:               "etp-local-ipv6-single-slice-remote",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1IPv6ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv6Remote},
			updated:            map[resource.Key][]string{},
		},
		// externalTrafficPolicy=Local && IPv6 && single slice && mixed endpoint
		{
			name:               "etp-local-ipv6-single-slice-mixed",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1IPv6ETPLocal},
			upsertedEndpoints:  []*k8s.Endpoints{eps1IPv6Mixed},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV6Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && Dual && two slices && local endpoint
		{
			name:               "etp-local-dual-two-slices-local",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocalTwoIngress},
			upsertedEndpoints: []*k8s.Endpoints{
				eps1IPv4Local,
				eps1IPv6Local,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
		// externalTrafficPolicy=Local && Dual && two slices && remote endpoint
		{
			name:               "etp-local-dual-two-slices-remote",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocalTwoIngress},
			upsertedEndpoints: []*k8s.Endpoints{
				eps1IPv4Remote,
				eps1IPv6Remote,
			},
			updated: map[resource.Key][]string{
				svc1Name: {},
			},
		},
		// externalTrafficPolicy=Local && Dual && two slices && mixed endpoint
		{
			name:               "etp-local-dual-two-slices-mixed",
			oldServiceSelector: &blueSelector,
			newServiceSelector: &blueSelector,
			advertised:         map[resource.Key][]string{},
			upsertedServices:   []*slim_corev1.Service{svc1ETPLocalTwoIngress},
			upsertedEndpoints: []*k8s.Endpoints{
				eps1IPv4Mixed,
				eps1IPv6Mixed,
			},
			updated: map[resource.Key][]string{
				svc1Name: {
					ingressV4Prefix,
					ingressV6Prefix,
				},
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// setup our test server, create a BgpServer, advertise the tt.advertised
			// networks, and store each returned Advertisement in testSC.PodCIDRAnnouncements
			srvParams := types.ServerParameters{
				Global: types.BGPGlobal{
					ASN:        64125,
					RouterID:   "127.0.0.1",
					ListenPort: -1,
				},
			}
			oldc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:        64125,
				Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector: tt.oldServiceSelector,
			}
			testSC, err := NewServerWithConfig(context.Background(), srvParams)
			if err != nil {
				t.Fatalf("failed to create test bgp server: %v", err)
			}
			testSC.Config = oldc

			diffstore := newFakeDiffStore[*slim_corev1.Service]()
			for _, obj := range tt.upsertedServices {
				diffstore.Upsert(obj)
			}
			for _, key := range tt.deletedServices {
				diffstore.Delete(key)
			}

			epDiffStore := newFakeDiffStore[*k8s.Endpoints]()
			for _, obj := range tt.upsertedEndpoints {
				epDiffStore.Upsert(obj)
			}

			reconciler := NewLBServiceReconciler(diffstore, epDiffStore).Reconciler.(*LBServiceReconciler)
			serviceAnnouncements := reconciler.getMetadata(testSC)

			for svcKey, cidrs := range tt.advertised {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					advrtResp, err := testSC.Server.AdvertisePath(context.Background(), types.PathRequest{
						Path: types.NewPathForPrefix(prefix),
					})
					if err != nil {
						t.Fatalf("failed to advertise initial svc lb cidr routes: %v", err)
					}

					serviceAnnouncements[svcKey] = append(serviceAnnouncements[svcKey], advrtResp.Path)
				}
			}

			newc := &v2alpha1api.CiliumBGPVirtualRouter{
				LocalASN:        64125,
				Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
				ServiceSelector: tt.newServiceSelector,
			}

			err = reconciler.Reconcile(context.Background(), ReconcileParams{
				CurrentServer: testSC,
				DesiredConfig: newc,
				CiliumNode: &v2api.CiliumNode{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: "node1",
					},
				},
			})
			if err != nil {
				t.Fatalf("failed to reconcile new lb svc advertisements: %v", err)
			}

			// if we disable exports of pod cidr ensure no advertisements are
			// still present.
			if tt.newServiceSelector == nil && !containsLbClass(tt.upsertedServices) {
				if len(serviceAnnouncements) > 0 {
					t.Fatal("disabled export but advertisements still present")
				}
			}

			log.Printf("%+v %+v", serviceAnnouncements, tt.updated)

			// ensure we see tt.updated in testSC.ServiceAnnouncements
			for svcKey, cidrs := range tt.updated {
				for _, cidr := range cidrs {
					prefix := netip.MustParsePrefix(cidr)
					var seen bool
					for _, advrt := range serviceAnnouncements[svcKey] {
						if advrt.NLRI.String() == prefix.String() {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("failed to advertise %v", cidr)
					}
				}
			}

			// ensure testSC.PodCIDRAnnouncements does not contain advertisements
			// not in tt.updated
			for svcKey, advrts := range serviceAnnouncements {
				for _, advrt := range advrts {
					var seen bool
					for _, cidr := range tt.updated[svcKey] {
						if advrt.NLRI.String() == cidr {
							seen = true
						}
					}
					if !seen {
						t.Fatalf("unwanted advert %+v", advrt)
					}
				}
			}

		})
	}
}

// TestReconcileAfterServerReinit reproduces issue #24975, validates service reconcile works after router-id is
// modified.
func TestReconcileAfterServerReinit(t *testing.T) {
	var (
		routerID        = "192.168.0.1"
		localPort       = int32(localListenPort)
		localASN        = int64(64125)
		newRouterID     = "192.168.0.2"
		diffstore       = newFakeDiffStore[*slim_corev1.Service]()
		epDiffStore     = newFakeDiffStore[*k8s.Endpoints]()
		serviceSelector = &slim_metav1.LabelSelector{MatchLabels: map[string]string{"color": "blue"}}
		obj             = &slim_corev1.Service{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "svc-1",
				Namespace: "default",
				Labels: map[string]string{
					"color": "blue",
				},
			},
			Spec: slim_corev1.ServiceSpec{
				Type: slim_corev1.ServiceTypeLoadBalancer,
			},
			Status: slim_corev1.ServiceStatus{
				LoadBalancer: slim_corev1.LoadBalancerStatus{
					Ingress: []slim_corev1.LoadBalancerIngress{
						{
							IP: "1.2.3.4",
						},
					},
				},
			},
		}
	)

	// Initial router configuration
	srvParams := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        64125,
			RouterID:   "127.0.0.1",
			ListenPort: -1,
		},
	}

	testSC, err := NewServerWithConfig(context.Background(), srvParams)
	require.NoError(t, err)

	originalServer := testSC.Server
	t.Cleanup(func() {
		originalServer.Stop() // stop our test server
		testSC.Server.Stop()  // stop any recreated server
	})

	// Validate pod CIDR and service announcements work as expected
	newc := &v2alpha1api.CiliumBGPVirtualRouter{
		LocalASN:        localASN,
		ExportPodCIDR:   pointer.Bool(true),
		Neighbors:       []v2alpha1api.CiliumBGPNeighbor{},
		ServiceSelector: serviceSelector,
	}

	exportPodCIDRReconciler := NewExportPodCIDRReconciler().Reconciler
	params := ReconcileParams{
		CurrentServer: testSC,
		DesiredConfig: newc,
		CiliumNode: &v2api.CiliumNode{
			ObjectMeta: meta_v1.ObjectMeta{
				Name: "Test Node",
				Annotations: map[string]string{
					"cilium.io/bgp-virtual-router.64125": fmt.Sprintf("router-id=%s,local-port=%d", routerID, localPort),
				},
			},
		},
	}

	err = exportPodCIDRReconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	diffstore.Upsert(obj)
	reconciler := NewLBServiceReconciler(diffstore, epDiffStore)
	err = reconciler.Reconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	// update server config, this is done outside of reconcilers
	testSC.Config = newc

	params.CiliumNode.Annotations = map[string]string{
		"cilium.io/bgp-virtual-router.64125": fmt.Sprintf("router-id=%s,local-port=%d", newRouterID, localPort),
	}

	preflightReconciler := NewPreflightReconciler().Reconciler

	// Trigger pre flight reconciler
	err = preflightReconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	// Test pod CIDR reconciler is working
	err = exportPodCIDRReconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)

	// Update LB service
	reconciler = NewLBServiceReconciler(diffstore, epDiffStore)
	err = reconciler.Reconciler.Reconcile(context.Background(), params)
	require.NoError(t, err)
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

func containsLbClass(svcs []*slim_corev1.Service) bool {
	for _, svc := range svcs {
		if svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == v2alpha1api.BGPLoadBalancerClass {
			return true
		}
	}
	return false
}
