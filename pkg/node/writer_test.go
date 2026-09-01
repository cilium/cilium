// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
)

func TestSourceWriter(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	deleteNode := func(src source.Source, identity types.Identity) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Delete(txn, src, identity)
	}

	n := &types.Node{Name: "node-1", Source: source.Kubernetes}
	require.True(t, upsert(n))

	txn := db.ReadTxn()
	got, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	require.Equal(t, source.Kubernetes, got.Source)

	got = got.DeepCopy()
	got.Statuses = got.Statuses.Set("test", reconciler.StatusDone())
	wtxn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(wtxn, got)
	require.NoError(t, err)
	wtxn.Commit()

	// An identical update preserves the completed status and table revision.
	revision := nodes.Revision(db.ReadTxn())
	require.False(t, upsert(n))
	require.Equal(t, revision, nodes.Revision(db.ReadTxn()))

	// A weaker source cannot replace or delete the object.
	weakNode := n.DeepCopy()
	weakNode.Source = source.ClusterMesh
	weakNode.Labels = map[string]string{"source": "mesh"}
	revision = nodes.Revision(db.ReadTxn())
	require.False(t, upsert(weakNode))
	require.False(t, deleteNode(weakNode.Source, weakNode.Identity()))
	require.Equal(t, revision, nodes.Revision(db.ReadTxn()))

	// A stronger source takes ownership and resets reconciliation statuses.
	strongNode := n.DeepCopy()
	strongNode.Source = source.KVStore
	strongNode.Labels = map[string]string{"source": "kvstore"}
	require.True(t, upsert(strongNode))
	got, _, found = nodes.Get(db.ReadTxn(), NodeByName("node-1"))
	require.True(t, found)
	require.Equal(t, source.KVStore, got.Source)
	require.Equal(t, reconciler.StatusKindPending, got.Statuses.Get("test").Kind)

	require.False(t, deleteNode(n.Source, n.Identity()))
	require.True(t, deleteNode(strongNode.Source, strongNode.Identity()))
	_, _, found = nodes.Get(db.ReadTxn(), NodeByName("node-1"))
	require.False(t, found)
}

func TestWriterReconcilerRegistration(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	get := func(name string) *Node {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found)
		return n
	}

	// Registration also adds a pending status to nodes that already exist.
	require.True(t, upsert(&types.Node{
		Name:   "existing",
		Source: source.Kubernetes,
	}))
	require.Empty(t, get("existing").Statuses.All())
	existing := get("existing").DeepCopy()
	existing.Statuses = existing.Statuses.Set("already-done", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, existing)
	require.NoError(t, err)
	txn.Commit()

	w.RegisterReconciler("wireguard")
	existing = get("existing")
	require.Equal(t,
		reconciler.StatusKindPending,
		existing.Statuses.Get("wireguard").Kind,
	)
	require.Contains(t, existing.Statuses.All(), "wireguard")
	require.Equal(t,
		reconciler.StatusKindDone,
		existing.Statuses.Get("already-done").Kind,
	)
	require.Equal(t, []string{"wireguard"}, requiredReconcilers(db, nodes, w))

	// Required reconcilers are materialized on newly inserted nodes. Seeing one
	// completed status therefore cannot hide another required pending status.
	w.RegisterReconciler("ipset")
	require.Equal(t,
		[]string{"ipset", "wireguard"},
		requiredReconcilers(db, nodes, w),
	)
	require.True(t, upsert(&types.Node{
		Name:   "new",
		Source: source.Kubernetes,
	}))

	// Duplicate registration panics
	require.Panics(t,
		func() {
			w.RegisterReconciler("ipset")
		})

	newNode := get("new").DeepCopy()
	require.Len(t, newNode.Statuses.All(), 2)
	newNode.Statuses = newNode.Statuses.Set("ipset", reconciler.StatusDone())
	txn = db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, newNode)
	require.NoError(t, err)
	txn.Commit()

	newNode = get("new")
	require.Equal(t,
		reconciler.StatusKindDone,
		newNode.Statuses.Get("ipset").Kind,
	)
	require.Equal(t,
		reconciler.StatusKindPending,
		newNode.Statuses.Get("wireguard").Kind,
	)

	w.UnregisterReconciler("wireguard")
	require.Equal(t, []string{"ipset"}, requiredReconcilers(db, nodes, w))
	existing = get("existing")
	newNode = get("new")
	require.NotContains(t, existing.Statuses.All(), "wireguard")
	require.NotContains(t, newNode.Statuses.All(), "wireguard")
	require.Equal(t,
		reconciler.StatusKindDone,
		existing.Statuses.Get("already-done").Kind,
	)
	require.Equal(t,
		reconciler.StatusKindDone,
		newNode.Statuses.Get("ipset").Kind,
	)

	// Duplicate unregistration does not rewrite the nodes.
	revision := nodes.Revision(db.ReadTxn())
	w.UnregisterReconciler("wireguard")
	require.Equal(t, revision, nodes.Revision(db.ReadTxn()))

	// Re-registering materializes a fresh pending status on all nodes.
	w.RegisterReconciler("wireguard")
	require.Contains(t, get("existing").Statuses.All(), "wireguard")
	require.Contains(t, get("new").Statuses.All(), "wireguard")
	require.Equal(t,
		reconciler.StatusKindPending,
		get("existing").Statuses.Get("wireguard").Kind,
	)
	require.Equal(t,
		reconciler.StatusKindPending,
		get("new").Statuses.Get("wireguard").Kind,
	)
}

func requiredReconcilers(
	db *statedb.DB,
	nodes statedb.RWTable[*Node],
	w *Writer,
) []string {
	txn := db.WriteTxn(nodes)
	defer txn.Abort()
	return w.getRequiredReconcilers(txn)
}

func TestWriterWaitUntilReconciled(t *testing.T) {
	newWriter := func(t *testing.T) (*statedb.DB, statedb.RWTable[*Node], *Writer) {
		t.Helper()
		db := statedb.New()
		nodes, err := NewNodeTable(db)
		require.NoError(t, err)
		return db, nodes, NewWriter(hivetest.Logger(t), db, nodes)
	}
	upsert := func(
		t *testing.T,
		db *statedb.DB,
		nodes statedb.RWTable[*Node],
		w *Writer,
		name string,
	) {
		t.Helper()
		txn := db.WriteTxn(nodes)
		require.True(t, w.Upsert(txn, &types.Node{
			Name:   name,
			Source: source.Kubernetes,
		}))
		txn.Commit()
	}
	setStatus := func(
		t *testing.T,
		db *statedb.DB,
		nodes statedb.RWTable[*Node],
		nodeName, reconcilerName string,
		status reconciler.Status,
	) {
		t.Helper()
		txn := db.WriteTxn(nodes)
		n, _, found := nodes.Get(txn, NodeByName(nodeName))
		require.True(t, found)
		updated := *n
		updated.Statuses = updated.Statuses.Set(reconcilerName, status)
		_, _, err := nodes.Insert(txn, &updated)
		require.NoError(t, err)
		txn.Commit()
	}
	waitUntilReconciled := func(
		t *testing.T,
		w *Writer,
		txn statedb.ReadTxn,
		requireDone bool,
	) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		require.NoError(t, w.WaitUntilReconciled(ctx, txn, requireDone))
	}

	t.Run("all statuses must finish", func(t *testing.T) {
		db, nodes, w := newWriter(t)
		w.RegisterReconciler("ipset")
		w.RegisterReconciler("wireguard")
		upsert(t, db, nodes, w, "node-1")
		setStatus(t, db, nodes, "node-1", "ipset", reconciler.StatusDone())

		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err := w.WaitUntilReconciled(ctx, db.ReadTxn(), false)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		setStatus(t, db, nodes, "node-1", "wireguard", reconciler.StatusError(errors.New("failed")))
		waitUntilReconciled(t, w, db.ReadTxn(), false)

		ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		err = w.WaitUntilReconciled(ctx, db.ReadTxn(), true)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		setStatus(t, db, nodes, "node-1", "wireguard", reconciler.StatusDone())
		waitUntilReconciled(t, w, db.ReadTxn(), true)
	})

	t.Run("deleted target is finished", func(t *testing.T) {
		db, nodes, w := newWriter(t)
		w.RegisterReconciler("wireguard")
		upsert(t, db, nodes, w, "node-1")
		txn := db.ReadTxn()

		wtxn := db.WriteTxn(nodes)
		n, _, found := nodes.Get(wtxn, NodeByName("node-1"))
		require.True(t, found)
		_, _, err := nodes.Delete(wtxn, n)
		require.NoError(t, err)
		wtxn.Commit()

		waitUntilReconciled(t, w, txn, false)
	})

	t.Run("new nodes are not included", func(t *testing.T) {
		db, nodes, w := newWriter(t)
		w.RegisterReconciler("wireguard")
		upsert(t, db, nodes, w, "initial")
		setStatus(t, db, nodes, "initial", "wireguard", reconciler.StatusDone())
		txn := db.ReadTxn()

		upsert(t, db, nodes, w, "later")
		waitUntilReconciled(t, w, txn, true)
	})
}

func TestSourceWriterDoesNotOverwriteLocalNode(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	local := &Node{
		Node: types.Node{
			Name:        "local",
			Source:      source.Local,
			IPAddresses: []types.Address{{IP: net.ParseIP("10.0.0.1")}},
		},
		Local: &LocalNodeInfo{},
	}
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()

	remote := &types.Node{Name: "local", Source: source.KubeAPIServer}
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, remote))
	require.False(t, w.Delete(txn, source.Local, remote.Identity()))
	txn.Commit()
	got, _, found := nodes.Get(db.ReadTxn(), NodeByName("local"))
	require.True(t, found)
	require.NotNil(t, got.Local)

	// The local row also owns its addresses regardless of source priority.
	remote = &types.Node{
		Name:        "remote",
		Source:      source.KubeAPIServer,
		IPAddresses: []types.Address{{IP: net.ParseIP("10.0.0.1")}},
	}
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, remote))
	txn.Commit()
	_, _, found = nodes.Get(db.ReadTxn(), NodeByName("remote"))
	require.False(t, found)
}

func TestWriterAddressConflicts(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	requireNode := func(name string) *Node {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found, name)
		return n
	}
	requireNoNode := func(name string) {
		_, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.False(t, found, name)
	}
	newNode := func(name string, src source.Source, addresses ...string) *types.Node {
		n := &types.Node{Name: name, Source: src}
		for _, address := range addresses {
			n.IPAddresses = append(n.IPAddresses, types.Address{IP: net.ParseIP(address)})
		}
		return n
	}

	// A stronger source takes the address and removes the weaker node.
	require.True(t, upsert(newNode("mesh", source.ClusterMesh, "10.0.0.1")))
	require.True(t, upsert(newNode("k8s", source.Kubernetes, "10.0.0.1")))
	requireNoNode("mesh")
	require.Equal(t, source.Kubernetes, requireNode("k8s").Source)

	// A weaker source cannot take an address from its current owner.
	require.False(t, upsert(newNode("weaker", source.ClusterMesh, "10.0.0.1")))
	requireNoNode("weaker")
	requireNode("k8s")

	// At equal priority the latest update wins.
	require.True(t, upsert(newNode("latest", source.Kubernetes, "10.0.0.1")))
	requireNoNode("k8s")
	requireNode("latest")

	// Health and ingress addresses participate in the same ownership checks.
	health := newNode("health", source.Kubernetes)
	health.IPv4HealthIP = iputil.AddrFrom(netip.MustParseAddr("10.0.0.4"))
	require.True(t, upsert(health))
	require.True(t, upsert(newNode("health-latest", source.Kubernetes, "10.0.0.4")))
	requireNoNode("health")
	requireNode("health-latest")

	ingress := newNode("ingress", source.Kubernetes)
	ingress.IPv4IngressIP = iputil.AddrFrom(netip.MustParseAddr("10.0.0.5"))
	require.True(t, upsert(ingress))
	require.True(t, upsert(newNode("ingress-latest", source.Kubernetes, "10.0.0.5")))
	requireNoNode("ingress")
	requireNode("ingress-latest")

	// Four-byte IPv4 and IPv4-mapped IPv6 representations are equivalent.
	mapped := newNode("mapped", source.Kubernetes)
	mapped.IPAddresses = []types.Address{{IP: net.IP{10, 0, 0, 6}}}
	require.True(t, upsert(mapped))
	require.True(t, upsert(newNode("mapped-latest", source.Kubernetes, "10.0.0.6")))
	requireNoNode("mapped")
	requireNode("mapped-latest")

	// Check all conflicts before deleting anything. This update could replace
	// the mesh node, but is rejected because it cannot replace the KVStore node.
	require.True(t, upsert(newNode("mesh-2", source.ClusterMesh, "10.0.0.2")))
	require.True(t, upsert(newNode("kvstore", source.KVStore, "10.0.0.3")))
	require.False(t, upsert(newNode(
		"mixed", source.Kubernetes, "10.0.0.2", "10.0.0.3",
	)))
	requireNode("mesh-2")
	requireNode("kvstore")
	requireNoNode("mixed")
}

func TestWriterAllowsSharedLocalRouterIP(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	w.isStaticLocalRouterIP = func(ip string) bool {
		return ip == "169.254.23.0" || ip == "fe80::"
	}

	routerAddresses := []types.Address{
		{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("169.254.23.0")},
		{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("fe80::")},
	}
	localAddresses := append(slices.Clone(routerAddresses), types.Address{
		Type: addressing.NodeInternalIP,
		IP:   net.ParseIP("10.0.0.1"),
	})
	local := &Node{
		Node: types.Node{
			Name:        "local",
			Source:      source.Local,
			IPAddresses: localAddresses,
		},
		Local: &LocalNodeInfo{},
	}
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()

	for _, name := range []string{"remote-1", "remote-2"} {
		txn = db.WriteTxn(nodes)
		require.True(t, w.Upsert(txn, &types.Node{
			Name:        name,
			Source:      source.CustomResource,
			IPAddresses: slices.Clone(routerAddresses),
		}))
		txn.Commit()
	}

	for _, name := range []string{"local", "remote-1", "remote-2"} {
		_, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found, name)
	}
	for _, address := range []netip.Addr{
		netip.MustParseAddr("169.254.23.0"),
		netip.MustParseAddr("fe80::"),
	} {
		var owners []string
		addrCluster := cmtypes.AddrClusterFrom(address, 0)
		for n := range nodes.List(db.ReadTxn(), NodeByAddress(addrCluster)) {
			owners = append(owners, n.Name)
		}
		require.ElementsMatch(t, []string{"local", "remote-1", "remote-2"}, owners)
	}

	// Matching a local node address alone is not enough: only the configured
	// Cilium internal router addresses may be shared.
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, &types.Node{
		Name:   "conflict",
		Source: source.CustomResource,
		IPAddresses: []types.Address{{
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
	}))
	txn.Commit()

	// The configured address remains conflicting when it is not advertised as
	// a Cilium internal IP.
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, &types.Node{
		Name:   "wrong-type",
		Source: source.CustomResource,
		IPAddresses: []types.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("169.254.23.0"),
		}},
	}))
	txn.Commit()
}

func TestWriterRefresh(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	n := &Node{Node: types.Node{Name: "node-1", Source: source.Kubernetes}}
	n.Statuses = n.Statuses.Set("test", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	done := make(chan error, 1)
	go func() { done <- w.Refresh(context.Background()) }()

	require.Eventually(t, func() bool {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName("node-1"))
		return found && n.Statuses.Get("test").Kind == reconciler.StatusKindPending
	}, time.Second, 10*time.Millisecond)

	txn = db.WriteTxn(nodes)
	n, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	n = n.DeepCopy()
	n.Statuses = n.Statuses.Set("test", reconciler.StatusDone())
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
	require.NoError(t, <-done)
}
