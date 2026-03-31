// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
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
		{
			Dst:       netip.MustParsePrefix("0.0.0.0/0"),
			Gw:        netip.MustParseAddr("192.168.0.3"),
			LinkIndex: 123,
			Priority:  100,
		},
		{
			Dst:       netip.MustParsePrefix("0.0.0.0/0"),
			Gw:        netip.MustParseAddr("192.168.0.4"),
			LinkIndex: 124,
			Priority:  200,
		},
		{
			Dst:       netip.MustParsePrefix("::/0"),
			Gw:        netip.MustParseAddr("fd00:10:0:1::1"),
			LinkIndex: 124,
			Priority:  200,
		},
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
				{
					Dst:       netip.MustParsePrefix("0.0.0.0/0"),
					Gw:        netip.MustParseAddr("192.168.0.3"),
					LinkIndex: 123,
					Priority:  200,
				},
				{
					Dst:       netip.MustParsePrefix("0.0.0.0/0"),
					Gw:        netip.MustParseAddr("192.168.0.4"),
					LinkIndex: 124,
					Priority:  100,
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

func setupStateDB(routes []*tables.Route) (*statedb.DB, error) {
	// create a test statedb
	db := statedb.New()

	if len(routes) == 0 {
		return db, nil
	}
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
		OperStatus: "up",
	})
	deviceTable.Insert(txn, &tables.Device{
		Name:       "eth1",
		Index:      124,
		OperStatus: "up",
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
				}
				if expPeer.PeerASN != nil {
					req.NotNil(actPeer.PeerASN)
					req.Equal(*expPeer.PeerASN, *actPeer.PeerASN)
				}
				break
			}
		}
		req.True(found, "Expected peer %s not found", expPeer.Name)
	}
}
