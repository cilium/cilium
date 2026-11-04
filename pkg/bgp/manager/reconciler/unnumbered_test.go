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

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// TestUnnumberedReconciler_DiscoveryFailureReporting covers the bookkeeping behind the
// warn-once logging of an unnumbered peer whose address cannot be discovered: the peer is
// remembered until it either recovers or its instance goes away.
func TestUnnumberedReconciler_DiscoveryFailureReporting(t *testing.T) {
	req := require.New(t)

	testInstance := &instance.BGPInstance{Name: "test-instance"}

	setTables := func(r *UnnumberedReconciler, neighbors []*tables.Neighbor) {
		db, err := setupStateDBWithNeighbors([]*tables.Route{
			defaultRouteEntry("192.168.0.3", 123, 100),
		}, neighbors)
		req.NoError(err)
		txn := db.ReadTxn()
		r.DB = db
		r.deviceTable = db.GetTable(txn, "devices").(statedb.Table[*tables.Device])
		r.neighborTable = db.GetTable(txn, "neighbors").(statedb.Table[*tables.Neighbor])
	}

	reconcile := func(r *UnnumberedReconciler) *v2.CiliumBGPNodeInstance {
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

	reconciler := &UnnumberedReconciler{logger: hivetest.Logger(t)}

	// No neighbor on eth0 yet, so the peer's address cannot be discovered. Its
	// configured interface remains available for the RA sender.
	setTables(reconciler, nil)
	config := reconcile(reconciler)
	req.Equal("eth0", config.Peers[0].AutoDiscovery.Unnumbered.Interface)
	req.Nil(config.Peers[0].PeerAddress)
	req.Contains(reconciler.discoveryFailed, "test-instance/peer-unnum")

	// The failure is tracked once, however many rounds it persists for.
	reconcile(reconciler)
	req.Len(reconciler.discoveryFailed, 1)

	// The neighbor appears: the peer is configured and no longer tracked.
	setTables(reconciler, []*tables.Neighbor{peerNeighbor("fe80::1", 123)})
	config = reconcile(reconciler)
	req.Equal("eth0", config.Peers[0].AutoDiscovery.Unnumbered.Interface)
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

// TestUnnumberedReconciler_UnnumberedPeerAddress covers picking the unnumbered peer's
// address out of the node's neighbor entries on the peering interface.
func TestUnnumberedReconciler_UnnumberedPeerAddress(t *testing.T) {
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
			reconciler := &UnnumberedReconciler{
				logger:          hivetest.Logger(t),
				DB:              db,
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
			req.Equal("eth0", config.Peers[0].AutoDiscovery.Unnumbered.Interface)
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

// TestUnnumberedReconciler_UnnumberedIgnoresOwnAddress ensures the node's own
// link-local address on the peering interface is never taken for the peer's.
func TestUnnumberedReconciler_UnnumberedIgnoresOwnAddress(t *testing.T) {
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
	reconciler := &UnnumberedReconciler{
		logger:          hivetest.Logger(t),
		DB:              db,
		deviceTable:     deviceTable,
		neighborTable:   db.GetTable(readTxn, "neighbors").(statedb.Table[*tables.Neighbor]),
		discoveryFailed: make(map[string]struct{}),
		unnumberedLinks: make(map[string]int),
	}

	addr, _, err := reconciler.getUnnumberedPeerAddress("eth0")
	req.NoError(err)
	req.Equal("fe80::1%eth0", addr)
}

// TestUnnumberedReconciler_NeighborChangeTrackerObserver ensures only the neighbors
// that can be an unnumbered peer address signal a reconciliation. The neighbors table sees
// every neighbor on the node, so an unfiltered observer would reconcile BGP on every ND
// state transition of every pod.
func TestUnnumberedReconciler_NeighborChangeTrackerObserver(t *testing.T) {
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

			reconciler := &UnnumberedReconciler{
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
