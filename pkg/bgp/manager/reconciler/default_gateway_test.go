// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/gobgp"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestDefaultGatewayReconciler_Basic(t *testing.T) {
	// Test basic functionality
	reconciler := &DefaultGatewayReconciler{
		logger: hivetest.Logger(t),
	}

	// Test Name and Priority
	assert.Equal(t, "DefaultGateway", reconciler.Name())
	assert.Equal(t, 10, reconciler.Priority())

	// Test Init and Cleanup
	bgpInstance := &instance.BGPInstance{Name: "test-instance"}
	err := reconciler.Init(bgpInstance)
	assert.NoError(t, err)
	reconciler.Cleanup(bgpInstance)
}

func TestDefaultGatewayReconciler_Reconcile(t *testing.T) {
	req := require.New(t)

	// Test data
	defaultRouteTable := []*tables.Route{
		defaultRouteEntry("192.168.0.3", 123, 100),
		defaultRouteEntry("192.168.0.4", 124, 200),
		defaultRouteEntry("fd00:10:0:1::1", 124, 200),
	}

	table := []struct {
		name             string
		routes           []*tables.Route
		newRoutes        []*tables.Route
		peers            []v2.CiliumBGPNodePeer
		expectedPeers    []v2.CiliumBGPNodePeer
		newPeers         []v2.CiliumBGPNodePeer
		expectedNewPeers []v2.CiliumBGPNodePeer
		err              error
	}{
		{
			name:   "default gateway no change",
			routes: defaultRouteTable,
			peers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-3",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-3",
					PeerAddress: ptr.To[string]("192.168.0.3"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			newPeers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-3",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedNewPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-3",
					PeerAddress: ptr.To[string]("192.168.0.3"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			name:   "add ipv4 default gateway peer",
			routes: defaultRouteTable,
			peers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-1",
					PeerAddress: ptr.To[string]("192.168.0.1"),
					PeerASN:     ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-1",
					PeerAddress: ptr.To[string]("192.168.0.1"),
					PeerASN:     ptr.To[int64](64124),
				},
			},
			newPeers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-3",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedNewPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-3",
					PeerAddress: ptr.To[string]("192.168.0.3"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			name:   "add ipv6 default gateway peer",
			routes: defaultRouteTable,
			peers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-2",
					PeerAddress: ptr.To[string]("192.168.0.2"),
					PeerASN:     ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-2",
					PeerAddress: ptr.To[string]("192.168.0.2"),
					PeerASN:     ptr.To[int64](64124),
				},
			},
			newPeers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-4",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv6",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedNewPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-4",
					PeerAddress: ptr.To[string]("fd00:10:0:1::1"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv6",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			// Unnumbered mode: the reconciler copies the configured interface
			// into PeerInterface. net0 is not in the device table, so no peer
			// address can be discovered on it - the interface is set anyway,
			// because the Router Advertisements which eventually populate the
			// neighbor entry are sent over it.
			name:   "unnumbered peer sets PeerInterface from config",
			routes: defaultRouteTable,
			peers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-unnum",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:       v2.BGPUnnumberedMode,
						Unnumbered: &v2.BGPUnnumbered{Interface: "net0"},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:          "peer-unnum",
					PeerInterface: ptr.To[string]("net0"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:       v2.BGPUnnumberedMode,
						Unnumbered: &v2.BGPUnnumbered{Interface: "net0"},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			newPeers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-unnum",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:       v2.BGPUnnumberedMode,
						Unnumbered: &v2.BGPUnnumbered{Interface: "net0"},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedNewPeers: []v2.CiliumBGPNodePeer{
				{
					Name:          "peer-unnum",
					PeerInterface: ptr.To[string]("net0"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode:       v2.BGPUnnumberedMode,
						Unnumbered: &v2.BGPUnnumbered{Interface: "net0"},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			name:   "update priority of default route",
			routes: defaultRouteTable,
			peers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-3",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-3",
					PeerAddress: ptr.To[string]("192.168.0.3"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			newRoutes: []*tables.Route{
				defaultRouteEntry("192.168.0.3", 123, 200),
				defaultRouteEntry("192.168.0.4", 124, 100),
			},
			newPeers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-3",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedNewPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-3",
					PeerAddress: ptr.To[string]("192.168.0.4"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			// A real default route in the main table is not beaten by a route in
			// another table, however good the other one's metric. The main-table route
			// deliberately carries the worse metric here, so what decides the outcome
			// is the filter and not the ordering by metric.
			name: "prefers the main-table default route over one in another table",
			routes: []*tables.Route{
				{
					// local table: a metric-0 "local default" over the wrong device
					Table:     2004,
					Type:      tables.RTN_LOCAL,
					Scope:     tables.RT_SCOPE_HOST,
					Dst:       ipv4Default,
					Gw:        netip.MustParseAddr("192.168.0.9"),
					LinkIndex: 123,
					Priority:  0,
				},
				{
					// Cilium's own table: a default route by way of cilium_host
					Table:     2005,
					Type:      tables.RTN_UNICAST,
					Dst:       ipv4Default,
					Gw:        netip.MustParseAddr("10.0.5.160"),
					LinkIndex: 124,
					Priority:  0,
				},
				defaultRouteEntry("192.168.0.3", 123, 1024),
			},
			peers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-tables-pref",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-tables-pref",
					PeerAddress: ptr.To[string]("192.168.0.3"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			// A node runs default routes in tables other than main - Cilium installs one
			// by way of cilium_host, and a local table holds a metric-0 "default dev lo".
			// Neither is the way off the node, so with no main-table unicast default
			// route there is nothing to discover at all.
			name: "ignores default routes outside the main table",
			routes: []*tables.Route{
				{
					// local table: "local default dev lo" with the best metric
					Table:     2004,
					Type:      tables.RTN_LOCAL,
					Scope:     tables.RT_SCOPE_HOST,
					Dst:       ipv4Default,
					Gw:        netip.MustParseAddr("192.168.0.9"),
					LinkIndex: 123,
					Priority:  0,
				},
				{
					// Cilium's own table: a default route by way of cilium_host
					Table:     2005,
					Type:      tables.RTN_UNICAST,
					Dst:       ipv4Default,
					Gw:        netip.MustParseAddr("10.0.5.160"),
					LinkIndex: 124,
					Priority:  0,
				},
			},
			peers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-tables",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			// A nil PeerAddress: no gateway was discovered.
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name: "peer-tables",
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
			},
			err: nil,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// Setup BGP instance
			testInstance, err := setupBGPInstance(hivetest.Logger(t))
			req.NoError(err)

			t.Cleanup(func() {
				testInstance.Router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
			})

			// Setup state database
			db, err := setupStateDB(tt.routes)
			req.NoError(err)

			txn := db.ReadTxn()
			routeTable := db.GetTable(txn, "routes").(statedb.Table[*tables.Route])
			deviceTable := db.GetTable(txn, "devices").(statedb.Table[*tables.Device])
			neighborTable := db.GetTable(txn, "neighbors").(statedb.Table[*tables.Neighbor])

			// Create reconciler
			reconciler := &DefaultGatewayReconciler{
				logger:        hivetest.Logger(t),
				DB:            db,
				routeTable:    routeTable,
				deviceTable:   deviceTable,
				neighborTable: neighborTable,
			}

			// Test initial reconciliation
			desiredConfig := &v2.CiliumBGPNodeInstance{
				Name:  "test-instance",
				Peers: tt.peers,
			}

			reconcileParams := ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: desiredConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}

			err = reconciler.Init(testInstance)
			req.NoError(err)
			defer reconciler.Cleanup(testInstance)

			err = reconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// Validate initial peers
			validatePeers(req, tt.expectedPeers, desiredConfig.Peers)

			// Test updated reconciliation
			routes := tt.routes
			if tt.newRoutes != nil {
				routes = tt.newRoutes
			}

			db, err = setupStateDB(routes)
			req.NoError(err)

			txn = db.ReadTxn()
			routeTable = db.GetTable(txn, "routes").(statedb.Table[*tables.Route])
			deviceTable = db.GetTable(txn, "devices").(statedb.Table[*tables.Device])
			neighborTable = db.GetTable(txn, "neighbors").(statedb.Table[*tables.Neighbor])

			reconciler.DB = db
			reconciler.routeTable = routeTable
			reconciler.deviceTable = deviceTable
			reconciler.neighborTable = neighborTable

			desiredConfig = &v2.CiliumBGPNodeInstance{
				Name:  "test-instance",
				Peers: tt.newPeers,
			}

			reconcileParams = ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: desiredConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}

			err = reconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// Validate updated peers
			validatePeers(req, tt.expectedNewPeers, desiredConfig.Peers)
		})
	}
}

// TestDefaultGatewayReconciler_DiscoveryFailureReporting covers the bookkeeping behind the
// warn-once logging of an unnumbered peer whose address cannot be discovered: the peer is
// remembered until it either recovers or its instance goes away.
func TestDefaultGatewayReconciler_DiscoveryFailureReporting(t *testing.T) {
	req := require.New(t)

	testInstance := &instance.BGPInstance{Name: "test-instance"}

	setTables := func(r *DefaultGatewayReconciler, neighbors []*tables.Neighbor) {
		db, err := setupStateDBWithNeighbors([]*tables.Route{
			defaultRouteEntry("192.168.0.3", 123, 100),
		}, neighbors)
		req.NoError(err)
		txn := db.ReadTxn()
		r.DB = db
		r.routeTable = db.GetTable(txn, "routes").(statedb.Table[*tables.Route])
		r.deviceTable = db.GetTable(txn, "devices").(statedb.Table[*tables.Device])
		r.neighborTable = db.GetTable(txn, "neighbors").(statedb.Table[*tables.Neighbor])
	}

	reconcile := func(r *DefaultGatewayReconciler) *v2.CiliumBGPNodeInstance {
		config := &v2.CiliumBGPNodeInstance{
			Name:  testInstance.Name,
			Peers: []v2.CiliumBGPNodePeer{unnumberedPeer("peer-unnum", "eth0")},
		}
		req.NoError(r.Reconcile(context.Background(), ReconcileParams{
			BGPInstance:   testInstance,
			DesiredConfig: config,
			CiliumNode:    &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "bgp-node"}},
		}))
		return config
	}

	reconciler := &DefaultGatewayReconciler{logger: hivetest.Logger(t)}

	// No neighbor on eth0 yet, so the peer's address cannot be discovered. Its
	// interface is set regardless, so the RAs that populate the entry are sent.
	setTables(reconciler, nil)
	config := reconcile(reconciler)
	req.Equal("eth0", ptr.Deref(config.Peers[0].PeerInterface, ""))
	req.Nil(config.Peers[0].PeerAddress)
	req.Contains(reconciler.discoveryFailed, "test-instance/peer-unnum")

	// The failure is tracked once, however many rounds it persists for.
	reconcile(reconciler)
	req.Len(reconciler.discoveryFailed, 1)

	// The neighbor appears: the peer is configured and no longer tracked.
	setTables(reconciler, []*tables.Neighbor{peerNeighbor("fe80::1", 123)})
	config = reconcile(reconciler)
	req.Equal("eth0", ptr.Deref(config.Peers[0].PeerInterface, ""))
	req.Equal("fe80::1%eth0", ptr.Deref(config.Peers[0].PeerAddress, ""))
	req.Empty(reconciler.discoveryFailed)

	// The neighbor goes away again, and this time the instance is deleted while
	// the peer is failing.
	setTables(reconciler, nil)
	reconcile(reconciler)
	req.Len(reconciler.discoveryFailed, 1)

	reconciler.Cleanup(testInstance)
	req.Empty(reconciler.discoveryFailed)
	req.Empty(reconciler.unnumberedLinks)

	// A peer that leaves the configuration stops being watched, so its link no
	// longer signals a reconciliation on every neighbor change.
	setTables(reconciler, []*tables.Neighbor{peerNeighbor("fe80::1", 123)})
	reconcile(reconciler)
	req.Len(reconciler.unnumberedLinks, 1)
	req.NoError(reconciler.Reconcile(context.Background(), ReconcileParams{
		BGPInstance:   testInstance,
		DesiredConfig: &v2.CiliumBGPNodeInstance{Name: testInstance.Name},
		CiliumNode:    &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "bgp-node"}},
	}))
	req.Empty(reconciler.unnumberedLinks)
	// Cleanup with a nil instance must not panic.
	req.NotPanics(func() { reconciler.Cleanup(nil) })
}

// TestDefaultGatewayReconciler_UnnumberedPeerAddress covers picking the unnumbered peer's
// address out of the node's neighbor entries on the peering interface.
func TestDefaultGatewayReconciler_UnnumberedPeerAddress(t *testing.T) {
	// The index of eth0, the peering interface.
	const linkIndex = 123

	failedNeighbor := peerNeighbor("fe80::dead", linkIndex)
	failedNeighbor.State = tables.NUD_FAILED

	staleNeighbor := peerNeighbor("fe80::2", linkIndex)
	staleNeighbor.State = tables.NUD_STALE

	hostNeighbor := peerNeighbor("fe80::3", linkIndex)
	hostNeighbor.Flags = 0

	table := []struct {
		name        string
		neighbors   []*tables.Neighbor
		expected    string
		expectedErr string
	}{
		{
			name:      "single link-local router neighbor",
			neighbors: []*tables.Neighbor{peerNeighbor("fe80::1", linkIndex)},
			expected:  "fe80::1%eth0",
		},
		{
			// A neighbor that has not been probed to completion is still the peer.
			name:      "stale neighbor is still usable",
			neighbors: []*tables.Neighbor{staleNeighbor},
			expected:  "fe80::2%eth0",
		},
		{
			// The peer announces itself as a router in its RAs, so it can be told
			// apart from other nodes sharing the link.
			name:      "router neighbor wins over a plain host",
			neighbors: []*tables.Neighbor{hostNeighbor, peerNeighbor("fe80::1", linkIndex)},
			expected:  "fe80::1%eth0",
		},
		{
			// Without a router to prefer, a single host neighbor is the best guess.
			name:      "single host neighbor is used when no router announced itself",
			neighbors: []*tables.Neighbor{hostNeighbor},
			expected:  "fe80::3%eth0",
		},
		{
			name:        "neighbor on another link is ignored",
			neighbors:   []*tables.Neighbor{peerNeighbor("fe80::1", 124)},
			expectedErr: "no IPv6 link-local neighbor discovered on interface eth0",
		},
		{
			name:        "global addresses are not link-local peers",
			neighbors:   []*tables.Neighbor{peerNeighbor("fd00::1", linkIndex), peerNeighbor("10.0.0.1", linkIndex)},
			expectedErr: "no IPv6 link-local neighbor discovered on interface eth0",
		},
		{
			name:        "failed neighbor is not dialed",
			neighbors:   []*tables.Neighbor{failedNeighbor},
			expectedErr: "no IPv6 link-local neighbor discovered on interface eth0",
		},
		{
			name:        "no neighbors at all",
			expectedErr: "no IPv6 link-local neighbor discovered on interface eth0",
		},
		{
			// Point-to-point only: with two routers there is no telling which one
			// the session is meant for.
			name:        "several router neighbors are ambiguous",
			neighbors:   []*tables.Neighbor{peerNeighbor("fe80::1", linkIndex), peerNeighbor("fe80::2", linkIndex)},
			expectedErr: "found 2 IPv6 link-local neighbors on interface eth0 ([fe80::1 fe80::2])",
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			db, err := setupStateDBWithNeighbors(nil, tt.neighbors)
			req.NoError(err)

			txn := db.ReadTxn()
			reconciler := &DefaultGatewayReconciler{
				logger:          hivetest.Logger(t),
				DB:              db,
				routeTable:      db.GetTable(txn, "routes").(statedb.Table[*tables.Route]),
				deviceTable:     db.GetTable(txn, "devices").(statedb.Table[*tables.Device]),
				neighborTable:   db.GetTable(txn, "neighbors").(statedb.Table[*tables.Neighbor]),
				discoveryFailed: make(map[string]struct{}),
				unnumberedLinks: make(map[string]int),
			}

			config := &v2.CiliumBGPNodeInstance{
				Name:  "test-instance",
				Peers: []v2.CiliumBGPNodePeer{unnumberedPeer("peer-unnum", "eth0")},
			}
			req.NoError(reconciler.Reconcile(context.Background(), ReconcileParams{
				BGPInstance:   &instance.BGPInstance{Name: "test-instance"},
				DesiredConfig: config,
				CiliumNode:    &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "bgp-node"}},
			}))

			// The interface is set either way: the Router Advertisements the peer
			// learns this node's own address from depend on it, and they are what
			// eventually populates the neighbor entry looked for here.
			req.Equal("eth0", ptr.Deref(config.Peers[0].PeerInterface, ""))
			// And the link is watched either way, so the neighbor appearing later
			// triggers another round.
			req.Equal(map[string]int{"test-instance/peer-unnum": linkIndex}, reconciler.unnumberedLinks)

			if tt.expectedErr != "" {
				req.Nil(config.Peers[0].PeerAddress)
				_, _, err := reconciler.getUnnumberedPeerAddress("eth0")
				req.ErrorContains(err, tt.expectedErr)
				return
			}
			req.Equal(tt.expected, ptr.Deref(config.Peers[0].PeerAddress, ""))
		})
	}
}

// TestDefaultGatewayReconciler_UnnumberedIgnoresOwnAddress ensures the node's own
// link-local address on the peering interface is never taken for the peer's.
func TestDefaultGatewayReconciler_UnnumberedIgnoresOwnAddress(t *testing.T) {
	req := require.New(t)

	db, err := setupStateDBWithNeighbors(nil, []*tables.Neighbor{
		peerNeighbor("fe80::1", 123),
		peerNeighbor("fe80::5", 123),
	})
	req.NoError(err)

	// Claim fe80::5 for eth0 itself.
	deviceTable := db.GetTable(db.ReadTxn(), "devices").(statedb.RWTable[*tables.Device])
	txn := db.WriteTxn(deviceTable)
	dev, _, found := deviceTable.Get(txn, tables.DeviceByName("eth0"))
	req.True(found)
	dev = dev.DeepCopy()
	dev.Addrs = []tables.DeviceAddress{{Addr: netip.MustParseAddr("fe80::5")}}
	_, _, err = deviceTable.Insert(txn, dev)
	req.NoError(err)
	txn.Commit()

	readTxn := db.ReadTxn()
	reconciler := &DefaultGatewayReconciler{
		logger:          hivetest.Logger(t),
		DB:              db,
		routeTable:      db.GetTable(readTxn, "routes").(statedb.Table[*tables.Route]),
		deviceTable:     deviceTable,
		neighborTable:   db.GetTable(readTxn, "neighbors").(statedb.Table[*tables.Neighbor]),
		discoveryFailed: make(map[string]struct{}),
		unnumberedLinks: make(map[string]int),
	}

	addr, _, err := reconciler.getUnnumberedPeerAddress("eth0")
	req.NoError(err)
	req.Equal("fe80::1%eth0", addr)
}

// TestDefaultGatewayReconciler_NeighborChangeTrackerObserver ensures only the neighbors
// that can be an unnumbered peer address signal a reconciliation. The neighbors table sees
// every neighbor on the node, so an unfiltered observer would reconcile BGP on every ND
// state transition of every pod.
func TestDefaultGatewayReconciler_NeighborChangeTrackerObserver(t *testing.T) {
	table := []struct {
		name     string
		neighbor *tables.Neighbor
		signaled bool
	}{
		{
			name:     "link-local neighbor on a watched link",
			neighbor: peerNeighbor("fe80::1", 123),
			signaled: true,
		},
		{
			name:     "link-local neighbor on an unwatched link",
			neighbor: peerNeighbor("fe80::1", 124),
			signaled: false,
		},
		{
			name:     "global address on a watched link",
			neighbor: peerNeighbor("fd00::1", 123),
			signaled: false,
		},
		{
			name:     "IPv4 neighbor on a watched link",
			neighbor: peerNeighbor("10.0.0.1", 123),
			signaled: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			reconciler := &DefaultGatewayReconciler{
				logger:          hivetest.Logger(t),
				unnumberedLinks: map[string]int{"test-instance/peer-unnum": 123},
			}
			sig := signaler.NewBGPCPSignaler()
			observer := reconciler.neighborChangeTrackerObserver(sig, hivetest.Logger(t))

			req.NoError(observer(context.Background(), statedb.Change[*tables.Neighbor]{Object: tt.neighbor}))

			if tt.signaled {
				req.Len(sig.Sig, 1)
			} else {
				req.Empty(sig.Sig)
			}
		})
	}
}

func TestDefaultGatewayTrackerObserver(t *testing.T) {
	table := []struct {
		name      string
		route     *tables.Route
		isDefault bool
		err       error
	}{
		{
			name: "IPv4 default route",
			route: &tables.Route{
				Table:     tables.RT_TABLE_MAIN,
				LinkIndex: 1,
				Dst:       ipv4Default,
				Gw:        netip.MustParseAddr("192.168.1.1"),
				Priority:  100,
			},
			isDefault: true,
		},
		{
			name: "IPv6 default route",
			route: &tables.Route{
				Table:     tables.RT_TABLE_MAIN,
				LinkIndex: 1,
				Dst:       ipv6Default,
				Gw:        netip.MustParseAddr("2001:db8::1"),
				Priority:  100,
			},
			isDefault: true,
		},
		{
			name: "Non-default IPv4 route",
			route: &tables.Route{
				Table:     tables.RT_TABLE_MAIN,
				LinkIndex: 1,
				Dst:       netip.MustParsePrefix("10.0.0.0/24"),
				Gw:        netip.MustParseAddr("192.168.1.1"),
				Priority:  100,
			},
			isDefault: false,
		},
		{
			name: "Non-default IPv6 route",
			route: &tables.Route{
				Table:     tables.RT_TABLE_MAIN,
				LinkIndex: 1,
				Dst:       netip.MustParsePrefix("fd00:10:0:1::/64"),
				Gw:        netip.MustParseAddr("fd00:10:0:1::1"),
				Priority:  100,
			},
			isDefault: false,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			signaler := signaler.NewBGPCPSignaler()
			logger := hivetest.Logger(t)

			// Get the observer function
			observerFunc := routeChangeTrackerObserver(signaler, logger)

			// Call the observer function with the test route
			err := observerFunc(context.Background(), statedb.Change[*tables.Route]{
				Object:   tt.route,
				Revision: 1,
				Deleted:  false,
			})
			require.NoError(t, err)

			// Check if an event was triggered by checking if there's a signal in the channel
			select {
			case <-signaler.Sig:
				if !tt.isDefault {
					t.Fatal("Unexpected signal received for non-default route")
				}
				// Success - we received a signal and its a default route
			default:
				if tt.isDefault {
					t.Fatal("Expected signal was not received")
				}
				// Success - we didn't receive a signal and its not a default route
			}
		})
	}
}

func TestDeviceChangeTrackerObserver(t *testing.T) {
	table := []struct {
		name   string
		device *tables.Device
	}{
		{
			name: "Device change",
			device: &tables.Device{
				Name:       "net0",
				Index:      1,
				OperStatus: "up",
			},
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			signaler := signaler.NewBGPCPSignaler()
			logger := hivetest.Logger(t)

			// Get the observer function
			observerFunc := deviceChangeTrackerObserver(signaler, logger)

			// Call the observer function with the test device
			err := observerFunc(context.Background(), statedb.Change[*tables.Device]{
				Object:   tt.device,
				Revision: 1,
				Deleted:  false,
			})
			require.NoError(t, err)

			// Check if an event was triggered by checking if there's a signal in the channel
			select {
			case <-signaler.Sig:
				// Success - we received a signal and its a device change
			default:
				t.Fatal("Expected signal was not received")
			}
		})
	}
}

func setupBGPInstance(logger *slog.Logger) (*instance.BGPInstance, error) {
	// our test BgpServer with our original router ID and local port
	srvParams := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        64125,
			RouterID:   "127.0.0.1",
			ListenPort: -1,
		},
	}

	testInstance, err := instance.NewBGPInstance(context.Background(), gobgp.NewRouterProvider(), logger, "test-instance", srvParams)
	return testInstance, err
}

// defaultRouteEntry builds a main-table unicast default route, the shape the reconciler
// selects from. The default route it covers follows the family of the gateway.
func defaultRouteEntry(gw string, linkIndex, priority int) *tables.Route {
	addr := netip.MustParseAddr(gw)
	dst := ipv6Default
	if addr.Is4() {
		dst = ipv4Default
	}
	return &tables.Route{
		Table:     tables.RT_TABLE_MAIN,
		Type:      tables.RTN_UNICAST,
		Dst:       dst,
		Gw:        addr,
		LinkIndex: linkIndex,
		Priority:  priority,
	}
}

// unnumberedPeer builds an unnumbered peer peering over the named interface.
func unnumberedPeer(name, iface string) v2.CiliumBGPNodePeer {
	return v2.CiliumBGPNodePeer{
		Name: name,
		AutoDiscovery: &v2.BGPAutoDiscovery{
			Mode:       v2.BGPUnnumberedMode,
			Unnumbered: &v2.BGPUnnumbered{Interface: iface},
		},
		PeerASN: ptr.To[int64](64124),
	}
}

// peerNeighbor builds the neighbor table entry an unnumbered peer is discovered from: a
// reachable IPv6 link-local neighbor that announced itself as a router.
func peerNeighbor(addr string, linkIndex int) *tables.Neighbor {
	return &tables.Neighbor{
		LinkIndex: linkIndex,
		IPAddr:    netip.MustParseAddr(addr),
		State:     tables.NUD_REACHABLE,
		Flags:     tables.NTF_ROUTER,
	}
}

// setupStateDB builds a state DB with the given routes and, on every device, the single
// link-local router neighbor an unnumbered peer is discovered from.
func setupStateDB(routes []*tables.Route) (*statedb.DB, error) {
	var neighbors []*tables.Neighbor
	for _, linkIndex := range []int{123, 124, 125, 126, 127, 128} {
		neighbors = append(neighbors, peerNeighbor("fe80::1", linkIndex))
	}
	return setupStateDBWithNeighbors(routes, neighbors)
}

func setupStateDBWithNeighbors(routes []*tables.Route, neighbors []*tables.Neighbor) (*statedb.DB, error) {
	// create a test statedb
	db := statedb.New()

	routeTable, err := tables.NewRouteTable(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create default gateway table: %w", err)
	}
	deviceTable, err := tables.NewDeviceTable(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create device table: %w", err)
	}
	neighborTable, err := tables.NewNeighborTable(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create neighbor table: %w", err)
	}
	txn := db.WriteTxn(routeTable, deviceTable, neighborTable)
	for _, r := range routes {
		routeTable.Insert(txn, r)
	}
	for _, n := range neighbors {
		neighborTable.Insert(txn, n)
	}

	deviceTable.Insert(txn, &tables.Device{
		Name:       "eth0",
		Index:      123,
		Flags:      net.FlagUp,
		OperStatus: "up",
	})
	deviceTable.Insert(txn, &tables.Device{
		Name:       "eth1",
		Index:      124,
		Flags:      net.FlagUp,
		OperStatus: "up",
	})
	// Operationally unknown, which point-to-point and dummy interfaces report even
	// when they are perfectly usable.
	deviceTable.Insert(txn, &tables.Device{
		Name:       "eth2",
		Index:      125,
		Flags:      net.FlagUp,
		OperStatus: linkOperStateUnknown,
	})
	// Operationally down.
	deviceTable.Insert(txn, &tables.Device{
		Name:       "eth3",
		Index:      126,
		Flags:      net.FlagUp,
		OperStatus: "down",
	})
	// Administratively down.
	deviceTable.Insert(txn, &tables.Device{
		Name:       "eth4",
		Index:      127,
		OperStatus: linkOperStateUnknown,
	})
	// Loopback: up and operationally unknown like any other loopback, but never a
	// way off the node.
	deviceTable.Insert(txn, &tables.Device{
		Name:       "lo",
		Index:      128,
		Flags:      net.FlagUp | net.FlagLoopback,
		OperStatus: linkOperStateUnknown,
	})
	txn.Commit()

	return db, nil
}

func validatePeers(req *require.Assertions, expected, actual []v2.CiliumBGPNodePeer) {
	req.Len(actual, len(expected))

	for _, expPeer := range expected {
		found := false
		for _, actPeer := range actual {
			if expPeer.Name == actPeer.Name {
				found = true
				if expPeer.PeerAddress != nil {
					req.NotNil(actPeer.PeerAddress)
					req.Equal(*expPeer.PeerAddress, *actPeer.PeerAddress)
				} else {
					req.Nil(actPeer.PeerAddress, "peer %s: unexpected PeerAddress", expPeer.Name)
				}
				if expPeer.PeerASN != nil {
					req.NotNil(actPeer.PeerASN)
					req.Equal(*expPeer.PeerASN, *actPeer.PeerASN)
				}
				if expPeer.PeerInterface != nil {
					req.NotNil(actPeer.PeerInterface)
					req.Equal(*expPeer.PeerInterface, *actPeer.PeerInterface)
				} else {
					req.Nil(actPeer.PeerInterface, "peer %s: unexpected PeerInterface", expPeer.Name)
				}
				break
			}
		}
		req.True(found, "Expected peer %s not found", expPeer.Name)
	}
}
