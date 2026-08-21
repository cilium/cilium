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
		defaultRouteEntry("0.0.0.0/0", "192.168.0.3", 123, 100),
		defaultRouteEntry("0.0.0.0/0", "192.168.0.4", 124, 200),
		defaultRouteEntry("::/0", "fd00:10:0:1::1", 124, 200),
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
			// into PeerInterface (with no PeerAddress) and leaves resolution of
			// the peer's link-local to gobgp via NeighborInterface.
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
			// Unnumbered mode with defaultGateway: the interface is not named in the
			// config, it is the one the default route of the requested family egresses.
			name:             "unnumbered peer derives interface from the ipv4 default route",
			routes:           defaultRouteTable,
			peers:            []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-v4", "ipv4")},
			expectedPeers:    []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-v4", "ipv4"), "eth0")},
			newPeers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-v4", "ipv4")},
			expectedNewPeers: []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-v4", "ipv4"), "eth0")},
			err:              nil,
		},
		{
			name:             "unnumbered peer derives interface from the ipv6 default route",
			routes:           defaultRouteTable,
			peers:            []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-v6", "ipv6")},
			expectedPeers:    []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-v6", "ipv6"), "eth1")},
			newPeers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-v6", "ipv6")},
			expectedNewPeers: []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-v6", "ipv6"), "eth1")},
			err:              nil,
		},
		{
			// A link-local gateway is the common case towards an unnumbered ToR. Only
			// the egress interface is taken from the route, so it is usable here -
			// while DefaultGateway mode, which needs the gateway as a peer address,
			// still rejects it.
			name: "unnumbered peer derives interface from a default route with a link-local gateway",
			routes: []*tables.Route{
				defaultRouteEntry("::/0", "fe80::1", 124, 100),
			},
			peers: []v2.CiliumBGPNodePeer{
				unnumberedGatewayPeer("peer-unnum-lla", "ipv6"),
				gatewayPeer("peer-gw-lla", "ipv6"),
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				withPeerInterface(unnumberedGatewayPeer("peer-unnum-lla", "ipv6"), "eth1"),
				gatewayPeer("peer-gw-lla", "ipv6"),
			},
			err: nil,
		},
		{
			// An on-link default route (default dev eth1, no gateway) also names the
			// interface facing the peer.
			name: "unnumbered peer derives interface from an on-link default route",
			routes: []*tables.Route{
				defaultRouteEntry("0.0.0.0/0", "", 124, 100),
			},
			peers: []v2.CiliumBGPNodePeer{
				unnumberedGatewayPeer("peer-unnum-onlink", "ipv4"),
				gatewayPeer("peer-gw-onlink", "ipv4"),
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				withPeerInterface(unnumberedGatewayPeer("peer-unnum-onlink", "ipv4"), "eth1"),
				gatewayPeer("peer-gw-onlink", "ipv4"),
			},
			err: nil,
		},
		{
			name: "unnumbered peer derives interface from a route over an operationally unknown device",
			routes: []*tables.Route{
				defaultRouteEntry("0.0.0.0/0", "169.254.100.0", 125, 100),
			},
			peers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-unknown", "ipv4")},
			expectedPeers: []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-unknown", "ipv4"), "eth2")},
			err:           nil,
		},
		{
			// Neither an operationally down nor an administratively down device can
			// carry the session, so the peer is left unconfigured rather than pinned
			// to a dead link. Reconciliation does not fail.
			name: "unnumbered peer is not configured when the default route egresses a down device",
			routes: []*tables.Route{
				defaultRouteEntry("0.0.0.0/0", "192.168.0.5", 126, 100),
				defaultRouteEntry("0.0.0.0/0", "192.168.0.6", 127, 200),
			},
			peers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-down", "ipv4")},
			expectedPeers: []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-down", "ipv4")},
			err:           nil,
		},
		{
			name:          "unnumbered peer is not configured without a default route of the requested family",
			routes:        []*tables.Route{},
			peers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-noroute", "ipv6")},
			expectedPeers: []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-noroute", "ipv6")},
			err:           nil,
		},
		{
			// Rejected by the CRD validation rules, but the reconciler must not act on
			// it either.
			name:   "unnumbered peer without unnumbered or defaultGateway is not configured",
			routes: defaultRouteTable,
			peers: []v2.CiliumBGPNodePeer{
				{
					Name:          "peer-unnum-empty",
					AutoDiscovery: &v2.BGPAutoDiscovery{Mode: v2.BGPUnnumberedMode},
					PeerASN:       ptr.To[int64](64124),
				},
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:          "peer-unnum-empty",
					AutoDiscovery: &v2.BGPAutoDiscovery{Mode: v2.BGPUnnumberedMode},
					PeerASN:       ptr.To[int64](64124),
				},
			},
			err: nil,
		},
		{
			// The default route with the lowest metric wins, and the derived interface
			// follows it when the metrics change.
			name:          "unnumbered peer follows the lowest metric default route",
			routes:        defaultRouteTable,
			peers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-metric", "ipv4")},
			expectedPeers: []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-metric", "ipv4"), "eth0")},
			newRoutes: []*tables.Route{
				defaultRouteEntry("0.0.0.0/0", "192.168.0.3", 123, 300),
				defaultRouteEntry("0.0.0.0/0", "192.168.0.4", 124, 200),
			},
			newPeers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-metric", "ipv4")},
			expectedNewPeers: []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-metric", "ipv4"), "eth1")},
			err:              nil,
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
				defaultRouteEntry("0.0.0.0/0", "192.168.0.3", 123, 200),
				defaultRouteEntry("0.0.0.0/0", "192.168.0.4", 124, 100),
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
			// A node runs default routes in tables other than main - Cilium installs one
			// by way of cilium_host, and a local table holds a metric-0 "default dev lo"
			// - and those outrank the real default route on metric. Only the main-table
			// unicast route is the way off the node.
			name: "ignores default routes outside the main table",
			routes: []*tables.Route{
				defaultRouteEntry("0.0.0.0/0", "192.168.0.3", 123, 1024),
				{
					// local table: "local default dev lo" with the best metric
					Table:     2004,
					Type:      tables.RTN_LOCAL,
					Scope:     tables.RT_SCOPE_HOST,
					Dst:       netip.MustParsePrefix("0.0.0.0/0"),
					Gw:        netip.MustParseAddr("192.168.0.9"),
					LinkIndex: 123,
					Priority:  0,
				},
				{
					// Cilium's own table: a default route with a better metric than the
					// real one
					Table:     2005,
					Type:      tables.RTN_UNICAST,
					Dst:       netip.MustParsePrefix("0.0.0.0/0"),
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
				unnumberedGatewayPeer("peer-unnum-tables", "ipv4"),
			},
			expectedPeers: []v2.CiliumBGPNodePeer{
				{
					Name:        "peer-tables",
					PeerAddress: ptr.To[string]("192.168.0.3"),
					AutoDiscovery: &v2.BGPAutoDiscovery{
						Mode: v2.BGPDefaultGatewayMode,
						DefaultGateway: &v2.DefaultGateway{
							AddressFamily: "ipv4",
						},
					},
					PeerASN: ptr.To[int64](64124),
				},
				// the same main-table route names the interface of the unnumbered peer
				withPeerInterface(unnumberedGatewayPeer("peer-unnum-tables", "ipv4"), "eth0"),
			},
			err: nil,
		},
		{
			// The loopback is never the way to a peer, whatever the metric says.
			name: "unnumbered peer ignores a default route over the loopback",
			routes: []*tables.Route{
				defaultRouteEntry("0.0.0.0/0", "", 128, 0),
				defaultRouteEntry("0.0.0.0/0", "169.254.100.0", 124, 1024),
			},
			peers:         []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum-lo", "ipv4")},
			expectedPeers: []v2.CiliumBGPNodePeer{withPeerInterface(unnumberedGatewayPeer("peer-unnum-lo", "ipv4"), "eth1")},
			err:           nil,
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

			// Create reconciler
			reconciler := &DefaultGatewayReconciler{
				logger:      hivetest.Logger(t),
				DB:          db,
				routeTable:  routeTable,
				deviceTable: deviceTable,
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

			reconciler.DB = db
			reconciler.routeTable = routeTable
			reconciler.deviceTable = deviceTable

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

// TestDefaultGatewayReconciler_DerivationFailureReporting covers the bookkeeping behind the
// warn-once logging of an unnumbered interface that cannot be derived: the peer is remembered
// until it either recovers or its instance goes away.
func TestDefaultGatewayReconciler_DerivationFailureReporting(t *testing.T) {
	req := require.New(t)

	testInstance := &instance.BGPInstance{Name: "test-instance"}

	setTables := func(r *DefaultGatewayReconciler, routes []*tables.Route) {
		db, err := setupStateDB(routes)
		req.NoError(err)
		txn := db.ReadTxn()
		r.DB = db
		r.routeTable = db.GetTable(txn, "routes").(statedb.Table[*tables.Route])
		r.deviceTable = db.GetTable(txn, "devices").(statedb.Table[*tables.Device])
	}

	reconcile := func(r *DefaultGatewayReconciler) *v2.CiliumBGPNodeInstance {
		config := &v2.CiliumBGPNodeInstance{
			Name:  testInstance.Name,
			Peers: []v2.CiliumBGPNodePeer{unnumberedGatewayPeer("peer-unnum", "ipv4")},
		}
		req.NoError(r.Reconcile(context.Background(), ReconcileParams{
			BGPInstance:   testInstance,
			DesiredConfig: config,
			CiliumNode:    &v2.CiliumNode{ObjectMeta: metav1.ObjectMeta{Name: "bgp-node"}},
		}))
		return config
	}

	reconciler := &DefaultGatewayReconciler{logger: hivetest.Logger(t)}

	// No default route yet, so the peer's interface cannot be derived.
	setTables(reconciler, nil)
	config := reconcile(reconciler)
	req.Nil(config.Peers[0].PeerInterface)
	req.Contains(reconciler.derivationFailed, "test-instance/peer-unnum")

	// The failure is tracked once, however many rounds it persists for.
	reconcile(reconciler)
	req.Len(reconciler.derivationFailed, 1)

	// The default route appears: the peer is configured and no longer tracked.
	setTables(reconciler, []*tables.Route{
		defaultRouteEntry("0.0.0.0/0", "192.168.0.3", 123, 100),
	})
	config = reconcile(reconciler)
	req.Equal("eth0", ptr.Deref(config.Peers[0].PeerInterface, ""))
	req.Empty(reconciler.derivationFailed)

	// The route goes away again, and this time the instance is deleted while the
	// peer is failing.
	setTables(reconciler, nil)
	reconcile(reconciler)
	req.Len(reconciler.derivationFailed, 1)

	reconciler.Cleanup(testInstance)
	req.Empty(reconciler.derivationFailed)
	// Cleanup with a nil instance must not panic.
	req.NotPanics(func() { reconciler.Cleanup(nil) })
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
// selects from. An empty gw builds an on-link route.
func defaultRouteEntry(dst, gw string, linkIndex, priority int) *tables.Route {
	route := &tables.Route{
		Table:     tables.RT_TABLE_MAIN,
		Type:      tables.RTN_UNICAST,
		Dst:       netip.MustParsePrefix(dst),
		LinkIndex: linkIndex,
		Priority:  priority,
	}
	if gw != "" {
		route.Gw = netip.MustParseAddr(gw)
	}
	return route
}

// unnumberedGatewayPeer builds an unnumbered peer whose interface is to be derived from the
// default route of the given address family.
func unnumberedGatewayPeer(name, addressFamily string) v2.CiliumBGPNodePeer {
	return v2.CiliumBGPNodePeer{
		Name: name,
		AutoDiscovery: &v2.BGPAutoDiscovery{
			Mode:           v2.BGPUnnumberedMode,
			DefaultGateway: &v2.DefaultGateway{AddressFamily: addressFamily},
		},
		PeerASN: ptr.To[int64](64124),
	}
}

// gatewayPeer builds a peer whose address is to be discovered from the default route of the
// given address family.
func gatewayPeer(name, addressFamily string) v2.CiliumBGPNodePeer {
	return v2.CiliumBGPNodePeer{
		Name: name,
		AutoDiscovery: &v2.BGPAutoDiscovery{
			Mode:           v2.BGPDefaultGatewayMode,
			DefaultGateway: &v2.DefaultGateway{AddressFamily: addressFamily},
		},
		PeerASN: ptr.To[int64](64124),
	}
}

// withPeerInterface returns the peer with the interface the reconciler is expected to have
// derived for it.
func withPeerInterface(peer v2.CiliumBGPNodePeer, iface string) v2.CiliumBGPNodePeer {
	peer.PeerInterface = ptr.To(iface)
	return peer
}

func setupStateDB(routes []*tables.Route) (*statedb.DB, error) {
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
	txn := db.WriteTxn(routeTable, deviceTable)
	for _, r := range routes {
		routeTable.Insert(txn, r)
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
