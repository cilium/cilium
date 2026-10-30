// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/agent/signaler"
	"github.com/cilium/cilium/pkg/bgp/config"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/time"
)

// Exercise the discovery -> RA -> neighbor handoff against the same StateDB
// through startup, route migration, and withdrawal. Each round gets fresh
// desired state, as it does when the controller copies its stored NodeConfig.
func TestUnnumberedReconciler_DefaultRouteTransitions(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	db, err := setupStateDBWithNeighbors(nil, nil)
	req.NoError(err)
	txn := db.ReadTxn()
	routes := db.GetTable(txn, "routes").(statedb.RWTable[*tables.Route])
	devices := db.GetTable(txn, "devices").(statedb.Table[*tables.Device])
	neighbors := db.GetTable(txn, "neighbors").(statedb.RWTable[*tables.Neighbor])
	discovery := &UnnumberedReconciler{
		logger: hivetest.Logger(t), DB: db,
		routeTable: routes, deviceTable: devices, neighborTable: neighbors,
	}
	ra := newTestRAReconciler(t, newFakeSenderFactory())
	peerConfigs := store.NewMockBGPCPResourceStore[*v2.CiliumBGPPeerConfig]()
	peerConfigs.Upsert(&v2.CiliumBGPPeerConfig{ObjectMeta: metav1.ObjectMeta{Name: "peer-config"}})
	neighbor := NewNeighborReconciler(NeighborReconcilerIn{
		Logger: hivetest.Logger(t), DB: db, DeviceTable: devices, PeerConfig: peerConfigs,
	}).Reconciler.(*NeighborReconciler)
	bgp := instance.NewFakeBGPInstance()
	req.NoError(neighbor.Init(bgp))
	t.Cleanup(func() { neighbor.Cleanup(bgp) })

	peer := unnumberedGatewayPeer("tor", "ipv4")
	peer.PeerConfigRef = &v2.PeerConfigReference{Name: "peer-config"}
	source := &v2.CiliumBGPNodeInstance{Name: bgp.Name, Peers: []v2.CiliumBGPNodePeer{peer}}
	original := source.DeepCopy()
	// Deliberately share AutoDiscovery with the source to check the resolved
	// interface handoff does not mutate its input, even without a deep copy.
	reconcile := func(iface, address string) {
		t.Helper()
		desired := &v2.CiliumBGPNodeInstance{Name: source.Name, Peers: append([]v2.CiliumBGPNodePeer(nil), source.Peers...)}
		params := ReconcileParams{BGPInstance: bgp, DesiredConfig: desired, CiliumNode: &v2.CiliumNode{}}
		req.NoError(discovery.Reconcile(ctx, params))
		req.NoError(ra.Reconcile(ctx, params))
		req.NoError(neighbor.Reconcile(ctx, params))
		req.Equal(original, source)
		if iface == "" {
			req.Empty(runningIfaces(ra))
			req.Empty(discovery.unnumberedLinks)
			req.Nil(desired.Peers[0].AutoDiscovery.Unnumbered)
		} else {
			req.Equal([]string{iface}, runningIfaces(ra))
			req.Equal(iface, desired.Peers[0].AutoDiscovery.Unnumbered.Interface)
			dev, _, found := devices.Get(db.ReadTxn(), tables.DeviceByName(iface))
			req.True(found)
			req.Equal(map[string]int{source.Name + "/tor": dev.Index}, discovery.unnumberedLinks)
		}
		if address == "" {
			req.Nil(desired.Peers[0].PeerAddress)
			req.Empty(neighbor.getMetadata(bgp))
			req.Contains(discovery.discoveryFailed, source.Name+"/tor")
		} else {
			req.Equal(address, ptr.Deref(desired.Peers[0].PeerAddress, ""))
			running := neighbor.getMetadata(bgp)
			req.Len(running, 1)
			req.Equal(address, ptr.Deref(running["tor"].Peer.PeerAddress, ""))
			req.Empty(discovery.discoveryFailed)
		}
	}

	reconcile("", "") // No route, no RA sender or BGP peer.
	routeA := defaultRouteEntry("169.254.100.0", 123, 100)
	wtxn := db.WriteTxn(routes)
	_, _, err = routes.Insert(wtxn, routeA)
	req.NoError(err)
	wtxn.Commit()
	reconcile("eth0", "") // Start RAs before the neighbor is learned.
	oldSender := ra.senders["eth0"]

	wtxn = db.WriteTxn(neighbors)
	_, _, err = neighbors.Insert(wtxn, peerNeighbor("fe80::1", 123))
	req.NoError(err)
	wtxn.Commit()
	reconcile("eth0", "fe80::1%eth0")

	// A better route moves discovery and RAs, even while the new peer is pending.
	routeB := defaultRouteEntry("169.254.100.0", 124, 50)
	wtxn = db.WriteTxn(routes)
	_, _, err = routes.Insert(wtxn, routeB)
	req.NoError(err)
	wtxn.Commit()
	reconcile("eth1", "")
	select {
	case <-oldSender.done:
	default:
		t.Fatal("old interface's RA sender is still running")
	}
	sig := signaler.NewBGPCPSignaler()
	observeNeighbor := discovery.neighborChangeTrackerObserver(sig, hivetest.Logger(t))
	req.NoError(observeNeighbor(ctx, statedb.Change[*tables.Neighbor]{Object: peerNeighbor("fe80::1", 123)}))
	req.Empty(sig.Sig, "the old link must no longer trigger discovery")
	req.NoError(observeNeighbor(ctx, statedb.Change[*tables.Neighbor]{Object: peerNeighbor("fe80::2", 124)}))
	req.Len(sig.Sig, 1, "the new link must trigger discovery")

	wtxn = db.WriteTxn(neighbors)
	_, _, err = neighbors.Insert(wtxn, peerNeighbor("fe80::2", 124))
	req.NoError(err)
	wtxn.Commit()
	reconcile("eth1", "fe80::2%eth1")
	lastSender := ra.senders["eth1"]

	wtxn = db.WriteTxn(routes)
	_, _, err = routes.Delete(wtxn, routeA)
	req.NoError(err)
	_, _, err = routes.Delete(wtxn, routeB)
	req.NoError(err)
	wtxn.Commit()
	reconcile("", "") // Withdraw stale peer and stop advertising on the old link.
	select {
	case <-lastSender.done:
	default:
		t.Fatal("RA sender survived route withdrawal")
	}
}

func TestUnnumberedReconciler_DefaultRouteSkipsUnusableDevice(t *testing.T) {
	db, err := setupStateDB([]*tables.Route{
		defaultRouteEntry("169.254.100.0", 126, 10), // Operationally down.
		defaultRouteEntry("169.254.100.0", 127, 20), // Administratively down.
		defaultRouteEntry("169.254.100.0", 999, 30), // Missing device.
		defaultRouteEntry("169.254.100.0", 124, 100),
	})
	require.NoError(t, err)
	txn := db.ReadTxn()
	r := &UnnumberedReconciler{
		DB:          db,
		routeTable:  db.GetTable(txn, "routes").(statedb.Table[*tables.Route]),
		deviceTable: db.GetTable(txn, "devices").(statedb.Table[*tables.Device]),
	}
	iface, err := r.getDefaultGatewayInterface(&v2.DefaultGateway{AddressFamily: "ipv4"})
	require.NoError(t, err)
	require.Equal(t, "eth1", iface)
}

// DefaultGateway's existing observer signals the shared controller even when
// there are no DefaultGateway-mode peers. Unnumbered needs no second observer.
func TestUnnumberedReconciler_DefaultRouteObserver(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()
	db := statedb.New()
	routes, err := tables.NewRouteTable(db)
	req.NoError(err)
	devices, err := tables.NewDeviceTable(db)
	req.NoError(err)
	neighbors, err := tables.NewNeighborTable(db)
	req.NoError(err)
	sig := signaler.NewBGPCPSignaler()
	logger := hivetest.Logger(t)
	h := hive.New(cell.Invoke(func(group job.Group) {
		NewDefaultGatewayReconciler(DefaultGatewayReconcilerIn{
			Logger: logger, BGPConfig: config.BGPConfig{Enable: true},
			DB: db, JobGroup: group, Signaler: sig, RouteTable: routes, DeviceTable: devices,
		})
		NewUnnumberedReconciler(UnnumberedReconcilerIn{
			Logger: logger, BGPConfig: config.BGPConfig{Enable: true},
			DB: db, JobGroup: group, Signaler: sig, RouteTable: routes,
			DeviceTable: devices, NeighborTable: neighbors,
		})
	}))
	req.NoError(h.Start(logger, ctx))
	t.Cleanup(func() { require.NoError(t, h.Stop(logger, ctx)) })
	waitForSignal := func() {
		t.Helper()
		select {
		case <-sig.Sig:
		case <-time.After(5 * time.Second):
			t.Fatal("default route change did not signal reconciliation")
		}
	}
	route := defaultRouteEntry("169.254.100.0", 123, 100)
	txn := db.WriteTxn(routes)
	_, _, err = routes.Insert(txn, route)
	req.NoError(err)
	txn.Commit()
	waitForSignal()
	txn = db.WriteTxn(routes)
	_, _, err = routes.Delete(txn, route)
	req.NoError(err)
	txn.Commit()
	waitForSignal()
}
