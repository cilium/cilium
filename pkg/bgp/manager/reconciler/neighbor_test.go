// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

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
				testInstance.Router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
			})

			params, nodeConfig := setupNeighbors(t, tt.neighbors)

			// setup initial neighbors
			neighborReconciler := NeighborReconcilerOut{
				Reconciler: &NeighborReconciler{
					logger:       params.Logger,
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
			validatePeerData(req, tt.neighbors, getRunningPeers(req, testInstance))

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
			validatePeerData(req, tt.newNeighbors, getRunningPeers(req, testInstance))
		})
	}
}

func TestNeighborReconciler_SourceInterfaceAddress(t *testing.T) {
	req := require.New(t)

	var (
		sourceInterfaceName   = "lo"
		sourceInterfaceV4Addr = "10.100.100.100"
		sourceInterfaceV6Addr = "fd00::aa:bb:100"

		peerV4 = PeerData{
			Peer: &v2.CiliumBGPNodePeer{
				Name:        "peer-v4",
				PeerAddress: ptr.To[string]("192.168.0.1"),
				PeerASN:     ptr.To[int64](64124),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-config",
				},
			},
			Config: &v2.CiliumBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					SourceInterface: &sourceInterfaceName,
				},
			},
		}
		peerV6 = PeerData{
			Peer: &v2.CiliumBGPNodePeer{
				Name:        "peer-v6",
				PeerAddress: ptr.To[string]("fc00::100:1"),
				PeerASN:     ptr.To[int64](64124),
				PeerConfigRef: &v2.PeerConfigReference{
					Name: "peer-config",
				},
			},
			Config: &v2.CiliumBGPPeerConfigSpec{
				Transport: &v2.CiliumBGPTransport{
					SourceInterface: &sourceInterfaceName,
				},
			},
		}
	)

	table := []struct {
		name                   string
		configuredNeighbors    []PeerData
		upsertDevices          []*tables.Device
		expectedNeighbors      []PeerData
		expectPeerLocalAddress map[string]string
	}{
		{
			name:                   "no device, no local address",
			configuredNeighbors:    []PeerData{peerV4, peerV6},
			expectedNeighbors:      []PeerData{},
			expectPeerLocalAddress: map[string]string{},
		},
		{
			name:                "add unrelated device, no local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 1,
					Name:  "eth0",
					Addrs: []tables.DeviceAddress{
						{Addr: netip.MustParseAddr("10.0.0.1")},
						{Addr: netip.MustParseAddr("fc00::aa:bb:1")},
					},
				},
			},
			expectedNeighbors:      []PeerData{},
			expectPeerLocalAddress: map[string]string{},
		},
		{
			name:                "add device with IPv4 address only, IPv4 local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 100,
					Name:  sourceInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.MustParseAddr(sourceInterfaceV4Addr)},
					},
				},
			},
			expectedNeighbors: []PeerData{peerV4},
			expectPeerLocalAddress: map[string]string{
				peerV4.Peer.Name: sourceInterfaceV4Addr,
			},
		},
		{
			name:                "add IPv6 device address, IPv4 + IPv6 local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 100,
					Name:  sourceInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.MustParseAddr(sourceInterfaceV4Addr)},
						{Addr: netip.MustParseAddr(sourceInterfaceV6Addr)},
					},
				},
			},
			expectedNeighbors: []PeerData{peerV4, peerV6},
			expectPeerLocalAddress: map[string]string{
				peerV4.Peer.Name: sourceInterfaceV4Addr,
				peerV6.Peer.Name: sourceInterfaceV6Addr,
			},
		},
		{
			name:                "Remove usable device addresses, no local address",
			configuredNeighbors: []PeerData{peerV4, peerV6},
			upsertDevices: []*tables.Device{
				{
					Index: 100,
					Name:  sourceInterfaceName,
					Addrs: []tables.DeviceAddress{
						{Addr: netip.IPv4Unspecified()},          // IPv4 unspecified should be ignored
						{Addr: netip.MustParseAddr("127.0.0.1")}, // IPv4 loopback should be ignored
						{Addr: netip.MustParseAddr("224.0.0.1")}, // IPv4 multicast should be ignored
						{Addr: netip.IPv6Unspecified()},          // IPv6 unspecified should be ignored
						{Addr: netip.MustParseAddr("::1")},       // IPv6 loopback should be ignored
						{Addr: netip.MustParseAddr("ff00::1")},   // IPv6 multicast should be ignored
						{Addr: netip.MustParseAddr("fe80::1")},   // IPv6 link-local should be ignored
					},
				},
			},
			expectedNeighbors:      []PeerData{},
			expectPeerLocalAddress: map[string]string{},
		},
	}

	// initialize test statedb
	db := statedb.New()
	deviceTable, err := tables.NewDeviceTable(db)
	req.NoError(err)

	peerConfigStore := store.NewMockBGPCPResourceStore[*v2.CiliumBGPPeerConfig]()

	neighborReconciler := NewNeighborReconciler(NeighborReconcilerIn{
		Logger:       hivetest.Logger(t),
		SecretStore:  nil,
		PeerConfig:   peerConfigStore,
		DaemonConfig: &option.DaemonConfig{},
		DB:           db,
		DeviceTable:  deviceTable,
	}).Reconciler.(*NeighborReconciler)

	// initialize test instance
	testInstance, err := setupBGPInstance(hivetest.Logger(t))
	req.NoError(err)
	t.Cleanup(func() {
		testInstance.Router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
	})
	neighborReconciler.Init(testInstance)
	defer neighborReconciler.Cleanup(testInstance)

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			// upsert devices in statedb
			if len(tt.upsertDevices) > 0 {
				wtxn := db.WriteTxn(deviceTable)
				for _, device := range tt.upsertDevices {
					_, _, err = deviceTable.Insert(wtxn, device)
					req.NoError(err)
				}
				wtxn.Commit()
			}

			// build desired node config
			nodeConfig := &v2.CiliumBGPNodeInstance{
				Name: "bgp-node",
			}
			for _, p := range tt.configuredNeighbors {
				obj := &v2.CiliumBGPPeerConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: p.Peer.PeerConfigRef.Name,
					},
					Spec: *p.Config.DeepCopy(),
				}
				peerConfigStore.Upsert(obj)
				nodeConfig.Peers = append(nodeConfig.Peers, *p.Peer)
			}

			// run reconciliation
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

			// validate running peers
			validatePeerData(req, tt.expectedNeighbors, getRunningPeers(req, testInstance))

			// validate local address used for peering
			runningMeta := neighborReconciler.getMetadata(testInstance)
			for expectPeer, expectAddr := range tt.expectPeerLocalAddress {
				req.NotNil(runningMeta[expectPeer], "peer %s is missing in the metadata", expectPeer)
				if expectAddr != "" {
					req.NotNil(runningMeta[expectPeer].Peer.LocalAddress, "LocalAddress is nil for the peer %s", expectPeer)
					req.Equal(expectAddr, *runningMeta[expectPeer].Peer.LocalAddress)
				} else {
					req.Nil(runningMeta[expectPeer].Peer.LocalAddress, "LocalAddress is expected to be for the peer %s", expectPeer)
				}
			}
		})
	}
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

func getRunningPeers(req *require.Assertions, instance *instance.BGPInstance) []PeerData {
	getPeerResp, err := instance.Router.GetPeerStateLegacy(context.Background())
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

func validatePeerData(req *require.Assertions, expected, running []PeerData) {
	req.Len(running, len(expected))

	for _, expPeer := range expected {
		found := false
		for _, runPeer := range running {
			req.NotNil(runPeer.Peer.PeerAddress)
			req.NotNil(runPeer.Peer.PeerASN)

			if *expPeer.Peer.PeerAddress == *runPeer.Peer.PeerAddress && *expPeer.Peer.PeerASN == *runPeer.Peer.PeerASN {
				found = true
				break
			}
		}
		req.True(found)
	}
}
