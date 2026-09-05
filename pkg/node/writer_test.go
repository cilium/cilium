// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
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

func TestWriterRestoresSourceFallback(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	w.RegisterReconciler("test")

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
	requireSource := func(name string, src source.Source) *Node {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found)
		require.Equal(t, src, n.Source)
		return n
	}

	k8s := &types.Node{Name: "node-1", Source: source.Kubernetes}
	require.True(t, upsert(k8s))

	// Restoring a displaced candidate starts a new reconciliation attempt.
	txn := db.WriteTxn(nodes)
	active, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	updated := active.DeepCopy()
	updated.Statuses = updated.Statuses.Set("test", reconciler.StatusDone())
	_, _, err = nodes.Insert(txn, updated)
	require.NoError(t, err)
	txn.Commit()

	kvstore := k8s.DeepCopy()
	kvstore.Source = source.KVStore
	require.True(t, upsert(kvstore))
	requireSource("node-1", source.KVStore)
	require.True(t, deleteNode(source.KVStore, kvstore.Identity()))
	restored := requireSource("node-1", source.Kubernetes)
	require.Equal(t, reconciler.StatusKindPending, restored.Statuses.Get("test").Kind)

	// A rejected candidate is also restored after its winner disappears.
	mesh := k8s.DeepCopy()
	mesh.Source = source.ClusterMesh
	require.False(t, upsert(mesh))
	require.True(t, deleteNode(source.Kubernetes, k8s.Identity()))
	requireSource("node-1", source.ClusterMesh)

	// Deleting a shadowed candidate prevents it from being restored later.
	require.True(t, upsert(k8s))
	require.False(t, deleteNode(source.ClusterMesh, mesh.Identity()))
	require.True(t, deleteNode(source.Kubernetes, k8s.Identity()))
	_, _, found = nodes.Get(db.ReadTxn(), NodeByName("node-1"))
	require.False(t, found)
}

func TestWriterReportsShadowedCandidates(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	health := &writerHealth{updates: make(chan writerHealthUpdate, 4)}
	w.health = health
	readHealth := func() writerHealthUpdate {
		select {
		case update := <-health.updates:
			return update
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for Writer health update")
			return writerHealthUpdate{}
		}
	}

	winner := &types.Node{Name: "node-1", Source: source.Kubernetes}
	txn := db.WriteTxn(nodes)
	require.True(t, w.Upsert(txn, winner))
	txn.Commit()
	update := readHealth()
	require.Equal(t, cell.StatusOK, update.level)
	require.Equal(t, "1 nodes (0 conflicts)", update.reason)

	shadowed := winner.DeepCopy()
	shadowed.Source = source.ClusterMesh
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, shadowed))
	txn.Commit()

	update = readHealth()
	require.Equal(t, cell.StatusDegraded, update.level)
	require.Equal(t, "1 nodes (1 conflicts): node-1", update.reason)
	require.EqualError(t, update.err, "node conflicts: 1")

	txn = db.WriteTxn(nodes)
	require.False(t, w.Delete(txn, shadowed.Source, shadowed.Identity()))
	txn.Commit()

	update = readHealth()
	require.Equal(t, cell.StatusOK, update.level)
	require.Equal(t, "1 nodes (0 conflicts)", update.reason)
}

type writerHealthUpdate struct {
	level  cell.Level
	reason string
	err    error
}

type writerHealth struct {
	updates chan writerHealthUpdate
}

func (h *writerHealth) OK(reason string) {
	h.updates <- writerHealthUpdate{level: cell.StatusOK, reason: reason}
}

func (h *writerHealth) Degraded(reason string, err error) {
	h.updates <- writerHealthUpdate{
		level:  cell.StatusDegraded,
		reason: reason,
		err:    err,
	}
}

func (*writerHealth) Stopped(string) {}

func (h *writerHealth) NewScope(string) cell.Health { return h }

func (*writerHealth) Close() {}

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
	require.Empty(t, maps.Collect(get("existing").Statuses.All()))
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
	require.Contains(t, maps.Collect(existing.Statuses.All()), "wireguard")
	require.Equal(t,
		reconciler.StatusKindDone,
		existing.Statuses.Get("already-done").Kind,
	)
	require.Equal(t, []NodeReconciler{"wireguard"}, requiredReconcilers(db, nodes, w))

	// Required reconcilers are materialized on newly inserted nodes. Seeing one
	// completed status therefore cannot hide another required pending status.
	w.RegisterReconciler("ipset")
	require.Equal(t,
		[]NodeReconciler{"ipset", "wireguard"},
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
	require.Len(t, maps.Collect(newNode.Statuses.All()), 2)
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
	require.Equal(t, []NodeReconciler{"ipset"}, requiredReconcilers(db, nodes, w))
	existing = get("existing")
	newNode = get("new")
	require.NotContains(t, maps.Collect(existing.Statuses.All()), "wireguard")
	require.NotContains(t, maps.Collect(newNode.Statuses.All()), "wireguard")
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
	require.Contains(t, maps.Collect(get("existing").Statuses.All()), "wireguard")
	require.Contains(t, maps.Collect(get("new").Statuses.All()), "wireguard")
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
) []NodeReconciler {
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
	deleteNode := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Delete(txn, n.Source, n.Identity())
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
	mesh := newNode("mesh", source.ClusterMesh, "10.0.0.1")
	k8s := newNode("k8s", source.Kubernetes, "10.0.0.1")
	require.True(t, upsert(mesh))
	require.True(t, upsert(k8s))
	requireNoNode("mesh")
	require.Equal(t, source.Kubernetes, requireNode("k8s").Source)

	// A weaker source cannot take an address from its current owner.
	weaker := newNode("weaker", source.ClusterMesh, "10.0.0.1")
	require.False(t, upsert(weaker))
	requireNoNode("weaker")
	requireNode("k8s")

	// At equal priority the latest update wins.
	latest := newNode("latest", source.Kubernetes, "10.0.0.1")
	require.True(t, upsert(latest))
	requireNoNode("k8s")
	requireNode("latest")

	// Fallback respects source priority first and recency within one priority.
	require.True(t, deleteNode(latest))
	requireNode("k8s")
	require.True(t, deleteNode(k8s))
	requireNode("weaker")
	requireNoNode("mesh")

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
	kvstore := newNode("kvstore", source.KVStore, "10.0.0.3")
	require.True(t, upsert(kvstore))
	require.False(t, upsert(newNode(
		"mixed", source.Kubernetes, "10.0.0.2", "10.0.0.3",
	)))
	requireNode("mesh-2")
	requireNode("kvstore")
	requireNoNode("mixed")

	// Removing the blocker restores the mixed candidate, which can then replace
	// the weaker node that shares its other address.
	require.True(t, deleteNode(kvstore))
	requireNoNode("mesh-2")
	requireNode("mixed")
}

func TestWriterRestoresFallbackWhenAddressIsReleased(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	newNode := func(name string, src source.Source, address string) *types.Node {
		return &types.Node{
			Name:        name,
			Source:      src,
			IPAddresses: []types.Address{{IP: net.ParseIP(address)}},
		}
	}

	winner := newNode("winner", source.Kubernetes, "10.0.0.1")
	fallback := newNode("fallback", source.ClusterMesh, "10.0.0.1")
	require.True(t, upsert(winner))
	require.False(t, upsert(fallback))

	winner = newNode("winner", source.Kubernetes, "10.0.0.2")
	require.True(t, upsert(winner))
	for _, name := range []string{"winner", "fallback"} {
		_, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found, name)
	}
}

func TestWriterClusterAwareAddressConflicts(t *testing.T) {
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
	newNode := func(
		name, cluster string,
		addressType addressing.AddressType,
		address string,
	) *types.Node {
		return &types.Node{
			Name:      name,
			Cluster:   cluster,
			ClusterID: 99,
			Source:    source.Kubernetes,
			IPAddresses: []types.Address{{
				Type: addressType,
				IP:   net.ParseIP(address),
			}},
		}
	}

	// The hook is installed during Hive invoke time, before producers write to
	// the table.
	w.SetPrefixClusterMutatorFn(func(n *types.Node) []cmtypes.PrefixClusterOpts {
		clusterIDs := map[string]uint32{"cluster-1": 1, "cluster-2": 2}
		return []cmtypes.PrefixClusterOpts{cmtypes.WithClusterID(clusterIDs[n.Cluster])}
	})

	// The serialized ClusterID is deliberately unrelated to address-space
	// qualification and must not affect the index.
	require.True(t, upsert(newNode(
		"node-1", "cluster-1", addressing.NodeCiliumInternalIP, "10.0.0.1",
	)))
	_, _, found := nodes.Get(
		db.ReadTxn(),
		NodeByAddress(cmtypes.AddrClusterFrom(netip.MustParseAddr("10.0.0.1"), 0)),
	)
	require.False(t, found)
	_, _, found = nodes.Get(
		db.ReadTxn(),
		NodeByAddress(cmtypes.AddrClusterFrom(netip.MustParseAddr("10.0.0.1"), 1)),
	)
	require.True(t, found)

	// Cluster-scoped Cilium internal addresses may overlap across clusters.
	require.True(t, upsert(newNode(
		"node-2", "cluster-2", addressing.NodeCiliumInternalIP, "10.0.0.1",
	)))
	requireNode("cluster-1/node-1")
	requireNode("cluster-2/node-2")

	// The same address in the same cluster still follows normal ownership rules.
	require.True(t, upsert(newNode(
		"latest", "cluster-1", addressing.NodeCiliumInternalIP, "10.0.0.1",
	)))
	requireNoNode("cluster-1/node-1")
	requireNode("cluster-1/latest")
	requireNode("cluster-2/node-2")

	// Underlay addresses remain globally scoped and conflict across clusters.
	require.True(t, upsert(newNode(
		"underlay-1", "cluster-1", addressing.NodeInternalIP, "192.0.2.1",
	)))
	require.True(t, upsert(newNode(
		"underlay-2", "cluster-2", addressing.NodeInternalIP, "192.0.2.1",
	)))
	requireNoNode("cluster-1/underlay-1")
	requireNode("cluster-2/underlay-2")
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
	w.RegisterReconciler("other")
	w.RegisterReconciler("test")

	n := &Node{Node: types.Node{Name: "node-1", Source: source.Kubernetes}}
	n.Statuses = n.Statuses.Set("other", reconciler.StatusPending())
	n.Statuses = n.Statuses.Set("test", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	done := make(chan error, 1)
	go func() { done <- w.Refresh(context.Background(), "test") }()

	require.Eventually(t, func() bool {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName("node-1"))
		return found &&
			n.Statuses.Get("test").Kind == reconciler.StatusKindPending &&
			n.Statuses.Get("other").Kind == reconciler.StatusKindPending
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

	require.ErrorContains(
		t,
		w.Refresh(context.Background(), "not-registered"),
		`node reconciler "not-registered" is not registered`,
	)
}

func TestWriterRefreshAll(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	w.RegisterReconciler("first")
	w.RegisterReconciler("second")

	n := &Node{Node: types.Node{Name: "node-1", Source: source.Kubernetes}}
	n.Statuses = n.Statuses.Set("first", reconciler.StatusDone())
	n.Statuses = n.Statuses.Set("second", reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()

	done := make(chan error, 1)
	go func() { done <- w.Refresh(context.Background()) }()

	require.Eventually(t, func() bool {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName("node-1"))
		return found &&
			n.Statuses.Get("first").Kind == reconciler.StatusKindPending &&
			n.Statuses.Get("second").Kind == reconciler.StatusKindPending
	}, time.Second, 10*time.Millisecond)

	txn = db.WriteTxn(nodes)
	n, _, found := nodes.Get(txn, NodeByName("node-1"))
	require.True(t, found)
	n = n.DeepCopy()
	n.Statuses = n.Statuses.Set("first", reconciler.StatusDone())
	n.Statuses = n.Statuses.Set("second", reconciler.StatusDone())
	_, _, err = nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
	require.NoError(t, <-done)
}
