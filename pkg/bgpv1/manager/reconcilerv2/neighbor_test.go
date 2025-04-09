// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/statedb"
)

type checks struct {
	holdTimer         bool
	connectRetryTimer bool
	keepaliveTimer    bool
	grRestartTime     bool
}

var (
	peer1 = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name:        "peer-1",
			PeerAddress: ptr.To[string]("192.168.0.1"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peer2 = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name:        "peer-2",
			PeerAddress: ptr.To[string]("192.168.0.2"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peer2UpdatedASN = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Peer.PeerASN = ptr.To[int64](64125)
		return peer2Copy
	}()

	peer2UpdatedTimers = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.Timers = &v2.CiliumBGPTimers{
			ConnectRetryTimeSeconds: ptr.To[int32](3),
			HoldTimeSeconds:         ptr.To[int32](9),
			KeepAliveTimeSeconds:    ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2UpdatedPorts = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.Transport = &v2.CiliumBGPTransport{
			PeerPort: ptr.To[int32](1790),
		}

		return peer2Copy
	}()

	peer2UpdatedGR = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.GracefulRestart = &v2.CiliumBGPNeighborGracefulRestart{
			Enabled:            true,
			RestartTimeSeconds: ptr.To[int32](3),
		}

		return peer2Copy
	}()

	peer2Pass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "a-password"

		return peer2Copy
	}()

	peer2UpdatePass = func() PeerData {
		peer2Copy := PeerData{
			Peer:     peer2.Peer.DeepCopy(),
			Config:   peer2.Config.DeepCopy(),
			Password: peer2.Password,
		}

		peer2Copy.Config.AuthSecretRef = ptr.To[string]("a-secret")
		peer2Copy.Password = "b-password"

		return peer2Copy
	}()

	peer3 = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name: "peer-3",
			AutoDiscovery: &v2.AutoDiscovery{
				Mode: "default-gateway",
				DefaultGateway: &v2.DefaultGateway{
					AddressFamily: "ipv4",
				},
			},
			PeerASN: ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	expectedPeer3 = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name:        "peer-3",
			PeerAddress: ptr.To[string]("192.168.0.3"),
			AutoDiscovery: &v2.AutoDiscovery{
				Mode: "default-gateway",
				DefaultGateway: &v2.DefaultGateway{
					AddressFamily: "ipv4",
				},
			},
			PeerASN: ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	expectedPeer3PriorityUpdated = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name:        "peer-4",
			PeerAddress: ptr.To[string]("192.168.0.4"),
			AutoDiscovery: &v2.AutoDiscovery{
				Mode: "default-gateway",
				DefaultGateway: &v2.DefaultGateway{
					AddressFamily: "ipv4",
				},
			},
			PeerASN: ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peer3UpdatedPeerAddress = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name:        "peer-3",
			PeerAddress: ptr.To[string]("192.168.0.3"),
			PeerASN:     ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	peer4 = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name: "peer-4",
			AutoDiscovery: &v2.AutoDiscovery{
				Mode: "default-gateway",
				DefaultGateway: &v2.DefaultGateway{
					AddressFamily: "ipv6",
				},
			},
			PeerASN: ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}

	expectedPeer4 = PeerData{
		Peer: &v2.CiliumBGPNodePeer{
			Name:        "peer-4",
			PeerAddress: ptr.To[string]("fd00:10:0:1::1"),
			AutoDiscovery: &v2.AutoDiscovery{
				Mode: "default-gateway",
				DefaultGateway: &v2.DefaultGateway{
					AddressFamily: "ipv6",
				},
			},
			PeerASN: ptr.To[int64](64124),
			PeerConfigRef: &v2.PeerConfigReference{
				Name: "peer-config",
			},
		},
		Config: &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](v2.DefaultBGPPeerPort),
			},
		},
	}
)

// TestNeighborReconciler_StaticPeer confirms the `neighborReconciler` function configures
// the desired BGP neighbors given a CiliumBGPVirtualRouter configuration with static peer address.
func TestNeighborReconciler_StaticPeer(t *testing.T) {
	req := require.New(t)

	table := []struct {
		name         string
		neighbors    []PeerData
		newNeighbors []PeerData
		secretStore  resource.Store[*slim_corev1.Secret]
		checks       checks
		err          error
	}{
		{
			name:         "no change",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2},
			err:          nil,
		},
		{
			name:         "add peers",
			neighbors:    []PeerData{peer1},
			newNeighbors: []PeerData{peer1, peer2},
			err:          nil,
		},
		{
			name:         "remove peers",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1},
			err:          nil,
		},
		{
			name:         "update config : ASN",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedASN},
			err:          nil,
		},
		{
			name:         "update config : timers",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedTimers},
			err:          nil,
		},
		{
			name:         "update config : ports",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedPorts},
			err:          nil,
		},
		{
			name:         "update config : graceful restart",
			neighbors:    []PeerData{peer1, peer2},
			newNeighbors: []PeerData{peer1, peer2UpdatedGR},
			err:          nil,
		},
		{
			name:         "update config : password",
			neighbors:    []PeerData{peer2},
			newNeighbors: []PeerData{peer2Pass},
			err:          nil,
		},
		{
			name:         "update config : password updated",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peer2UpdatePass},
			err:          nil,
		},
		{
			name:         "update config : password removed",
			neighbors:    []PeerData{peer2Pass},
			newNeighbors: []PeerData{peer2},
			err:          nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			testInstance, err := setupBGPInstance(hivetest.Logger(t))
			req.NoError(err)

			t.Cleanup(func() {
				testInstance.Router.Stop()
			})

			params, nodeConfig := setupNeighbors(t, tt.neighbors)

			// setup initial neighbors
			neighborReconciler := NeighborReconcilerOut{
				Reconciler: &NeighborReconciler{
					logger:       params.Logger,
					DB:           params.DB,
					SecretStore:  params.SecretStore,
					PeerConfig:   params.PeerConfig,
					DaemonConfig: params.DaemonConfig,
					metadata:     make(map[string]NeighborReconcilerMetadata),
				},
			}.Reconciler
			neighborReconciler.Init(testInstance)
			defer neighborReconciler.Cleanup(testInstance)
			reconcileParams := ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: nodeConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.neighbors, getRunningPeers(req, testInstance), tt.checks)

			// update neighbors

			params, nodeConfig = setupNeighbors(t, tt.newNeighbors)
			neighborReconciler.(*NeighborReconciler).PeerConfig = params.PeerConfig
			neighborReconciler.(*NeighborReconciler).SecretStore = params.SecretStore
			reconcileParams = ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: nodeConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.newNeighbors, getRunningPeers(req, testInstance), tt.checks)
		})
	}
}

func TestNeighborReconciler_DefaultGateway(t *testing.T) {
	req := require.New(t)
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
		name                 string
		routes               []*tables.Route
		newRoutes            []*tables.Route
		neighbors            []PeerData
		expectedNeighbors    []PeerData
		newNeighbors         []PeerData
		expectedNewNeighbors []PeerData
		checks               checks
		err                  error
	}{
		{
			name:                 "default gateway no change",
			routes:               defaultRouteTable,
			neighbors:            []PeerData{peer3},
			expectedNeighbors:    []PeerData{expectedPeer3},
			newNeighbors:         []PeerData{peer3},
			expectedNewNeighbors: []PeerData{expectedPeer3},
			err:                  nil,
		},
		{
			name:                 "add ipv4 default gateway peer",
			routes:               defaultRouteTable,
			neighbors:            []PeerData{peer1},
			expectedNeighbors:    []PeerData{peer1},
			newNeighbors:         []PeerData{peer3},
			expectedNewNeighbors: []PeerData{expectedPeer3},
			err:                  nil,
		},
		{
			name:                 "add ipv6 default gateway peer",
			routes:               defaultRouteTable,
			neighbors:            []PeerData{peer2},
			expectedNeighbors:    []PeerData{peer2},
			newNeighbors:         []PeerData{peer4},
			expectedNewNeighbors: []PeerData{expectedPeer4},
			err:                  nil,
		},
		{
			name:              "remove default gateway peer",
			routes:            defaultRouteTable,
			neighbors:         []PeerData{peer3, peer2},
			expectedNeighbors: []PeerData{expectedPeer3, peer2},

			newNeighbors:         []PeerData{peer2},
			expectedNewNeighbors: []PeerData{peer2},
			err:                  nil,
		},
		{
			name:                 "update default gateway to static peer",
			routes:               defaultRouteTable,
			neighbors:            []PeerData{peer3},
			expectedNeighbors:    []PeerData{expectedPeer3},
			newNeighbors:         []PeerData{peer3UpdatedPeerAddress},
			expectedNewNeighbors: []PeerData{peer3UpdatedPeerAddress},
			err:                  nil,
		},
		{
			name:              "update priority of default route",
			routes:            defaultRouteTable,
			neighbors:         []PeerData{peer3},
			expectedNeighbors: []PeerData{expectedPeer3},
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
			newNeighbors:         []PeerData{peer3},
			expectedNewNeighbors: []PeerData{expectedPeer3PriorityUpdated},
			err:                  nil,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {

			testInstance, err := setupBGPInstance(hivetest.Logger(t))
			req.NoError(err)

			t.Cleanup(func() {
				testInstance.Router.Stop()
			})

			params, nodeConfig := setupNeighbors(t, tt.neighbors)

			db, err := setupStateDB(tt.routes)
			req.NoError(err)
			params.DB = db

			// setup initial neighbors
			neighborReconciler := NeighborReconcilerOut{
				Reconciler: &NeighborReconciler{
					logger:       params.Logger,
					DB:           params.DB,
					SecretStore:  params.SecretStore,
					PeerConfig:   params.PeerConfig,
					DaemonConfig: params.DaemonConfig,
					metadata:     make(map[string]NeighborReconcilerMetadata),
				},
			}.Reconciler
			neighborReconciler.Init(testInstance)
			defer neighborReconciler.Cleanup(testInstance)
			reconcileParams := ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: nodeConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.expectedNeighbors, getRunningPeers(req, testInstance), tt.checks)

			routes := tt.routes
			if tt.newRoutes != nil {
				routes = tt.newRoutes
			}
			// update neighbors
			params, nodeConfig = setupNeighbors(t, tt.newNeighbors)
			db, err = setupStateDB(routes)
			req.NoError(err)
			params.DB = db
			neighborReconciler.(*NeighborReconciler).PeerConfig = params.PeerConfig
			neighborReconciler.(*NeighborReconciler).DB = params.DB
			reconcileParams = ReconcileParams{
				BGPInstance:   testInstance,
				DesiredConfig: nodeConfig,
				CiliumNode: &v2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bgp-node",
					},
				},
			}
			err = neighborReconciler.Reconcile(context.Background(), reconcileParams)
			req.NoError(err)

			// validate neighbors
			validatePeers(req, tt.expectedNewNeighbors, getRunningPeers(req, testInstance), tt.checks)
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

	testInstance, err := instance.NewBGPInstance(context.Background(), logger, "test-instance", srvParams)
	return testInstance, err
}

func setupNeighbors(t *testing.T, peers []PeerData) (NeighborReconcilerIn, *v2.CiliumBGPNodeInstance) {
	// Desired BGP Node config
	nodeConfig := &v2.CiliumBGPNodeInstance{
		Name: "bgp-node",
	}

	// setup fake store for peer config
	var objects []*v2.CiliumBGPPeerConfig
	for _, p := range peers {
		obj := &v2.CiliumBGPPeerConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: p.Peer.PeerConfigRef.Name,
			},
			Spec: *p.Config.DeepCopy(),
		}
		objects = append(objects, obj)
		nodeConfig.Peers = append(nodeConfig.Peers, *p.Peer)
	}
	peerConfigStore := store.InitMockStore[*v2.CiliumBGPPeerConfig](objects)

	// setup secret store
	secrets := make(map[string][]byte)
	for _, p := range peers {
		if p.Config.AuthSecretRef != nil {
			secrets[*p.Config.AuthSecretRef] = []byte(p.Password)
		}
	}
	var secretObjs []*slim_corev1.Secret
	for _, s := range secrets {
		secretObjs = append(secretObjs, &slim_corev1.Secret{
			ObjectMeta: slim_metav1.ObjectMeta{
				Namespace: "bgp-secrets",
				Name:      "a-secret",
			},
			Data: map[string]slim_corev1.Bytes{"password": slim_corev1.Bytes(s)},
		})
	}
	secretStore := store.InitMockStore[*slim_corev1.Secret](secretObjs)

	return NeighborReconcilerIn{
		Logger:       hivetest.Logger(t),
		SecretStore:  secretStore,
		PeerConfig:   peerConfigStore,
		DaemonConfig: &option.DaemonConfig{BGPSecretsNamespace: "bgp-secrets"},
	}, nodeConfig
}

func setupStateDB(routes []*tables.Route) (*statedb.DB, error) {
	// create a test statedb
	db := statedb.New()

	if len(routes) == 0 {
		return db, nil
	}
	routeTable, err := tables.NewRouteTable()
	if err != nil {
		return nil, fmt.Errorf("failed to create default gateway table: %v", err)
	}
	deviceTable, err := tables.NewDeviceTable()
	if err != nil {
		return nil, fmt.Errorf("failed to create device table: %v", err)
	}
	err = db.RegisterTable(routeTable)
	if err != nil {
		return nil, fmt.Errorf("failed to register default gateway table: %v", err)
	}
	err = db.RegisterTable(deviceTable)
	if err != nil {
		return nil, fmt.Errorf("failed to register device table: %v", err)
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

func validatePeers(req *require.Assertions, expected, running []PeerData, checks checks) {
	req.Len(running, len(expected))

	for _, expPeer := range expected {
		found := false
		for _, runPeer := range running {
			req.NotNil(runPeer.Peer.PeerAddress)
			req.NotNil(runPeer.Peer.PeerASN)

			if *expPeer.Peer.PeerAddress == *runPeer.Peer.PeerAddress && *expPeer.Peer.PeerASN == *runPeer.Peer.PeerASN {
				found = true

				if checks.holdTimer {
					req.Equal(*expPeer.Config.Timers.HoldTimeSeconds, *runPeer.Config.Timers.HoldTimeSeconds)
				}

				if checks.connectRetryTimer {
					req.Equal(*expPeer.Config.Timers.ConnectRetryTimeSeconds, *runPeer.Config.Timers.ConnectRetryTimeSeconds)
				}

				if checks.keepaliveTimer {
					req.Equal(*expPeer.Config.Timers.KeepAliveTimeSeconds, *runPeer.Config.Timers.KeepAliveTimeSeconds)
				}

				if checks.grRestartTime {
					req.Equal(expPeer.Config.GracefulRestart.Enabled, runPeer.Config.GracefulRestart.Enabled)
					req.Equal(*expPeer.Config.GracefulRestart.RestartTimeSeconds, *runPeer.Config.GracefulRestart.RestartTimeSeconds)
				}

				if expPeer.Password != "" {
					req.NotEmpty(runPeer.Password)
				}

				break
			}
		}
		req.True(found)
	}
}

func getRunningPeers(req *require.Assertions, instance *instance.BGPInstance) []PeerData {
	getPeerResp, err := instance.Router.GetPeerState(context.Background())
	req.NoError(err)

	var runningPeers []PeerData
	for _, peer := range getPeerResp.Peers {
		peerObj := &v2.CiliumBGPNodePeer{
			PeerAddress: ptr.To[string](peer.PeerAddress),
			PeerASN:     ptr.To[int64](peer.PeerAsn),
		}

		peerConfObj := &v2.CiliumBGPPeerConfigSpec{
			Transport: &v2.CiliumBGPTransport{
				PeerPort: ptr.To[int32](int32(peer.PeerPort)),
			},
			Timers: &v2.CiliumBGPTimers{
				ConnectRetryTimeSeconds: ptr.To[int32](int32(peer.ConnectRetryTimeSeconds)),
				HoldTimeSeconds:         ptr.To[int32](int32(peer.ConfiguredHoldTimeSeconds)),
				KeepAliveTimeSeconds:    ptr.To[int32](int32(peer.ConfiguredKeepAliveTimeSeconds)),
			},
			GracefulRestart: &v2.CiliumBGPNeighborGracefulRestart{
				Enabled:            peer.GracefulRestart.Enabled,
				RestartTimeSeconds: ptr.To[int32](int32(peer.GracefulRestart.RestartTimeSeconds)),
			},
			EBGPMultihop: ptr.To[int32](int32(peer.EbgpMultihopTTL)),
		}

		password := ""
		if peer.TCPPasswordEnabled {
			password = "something-is-set-dont-care-what"
		}

		runningPeers = append(runningPeers, PeerData{
			Peer:     peerObj,
			Config:   peerConfObj,
			Password: password,
		})
	}
	return runningPeers
}
