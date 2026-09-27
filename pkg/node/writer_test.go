// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
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
			Name:   "local",
			Source: source.Local,
			IPAddresses: []types.Address{{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			}},
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
		Name:   "remote",
		Source: source.KubeAPIServer,
		IPAddresses: []types.Address{{
			Type: addressing.NodeExternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
	}
	txn = db.WriteTxn(nodes)
	require.False(t, w.Upsert(txn, remote))
	txn.Commit()
	_, _, found = nodes.Get(db.ReadTxn(), NodeByName("remote"))
	require.False(t, found)
}

func TestWriterAllowsRemoteAddressConflicts(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	upsert := func(n *types.Node) bool {
		txn := db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	newNode := func(name string, src source.Source) *types.Node {
		return &types.Node{
			Name:   name,
			Source: src,
			IPAddresses: []types.Address{{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			}},
		}
	}

	// Address ownership between remote nodes is deliberately not arbitrated.
	// This permits both equal-source and different-source conflicts.
	require.True(t, upsert(newNode("mesh", source.ClusterMesh)))
	require.True(t, upsert(newNode("k8s-1", source.Kubernetes)))
	require.True(t, upsert(newNode("k8s-2", source.Kubernetes)))

	var owners []string
	address := cmtypes.AddrClusterFrom(netip.MustParseAddr("10.0.0.1"), 0)
	for n := range nodes.List(db.ReadTxn(), NodeByAddress(address)) {
		owners = append(owners, n.Name)
	}
	require.ElementsMatch(t, []string{"mesh", "k8s-1", "k8s-2"}, owners)
}

func TestWriterClusterAwareAddressIndex(t *testing.T) {
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

	// Address conflicts between remote nodes are allowed within a cluster.
	require.True(t, upsert(newNode(
		"node-3", "cluster-1", addressing.NodeCiliumInternalIP, "10.0.0.1",
	)))
	requireNode("cluster-1/node-1")
	requireNode("cluster-1/node-3")
	requireNode("cluster-2/node-2")

	// Underlay addresses remain globally indexed, but may also be shared.
	require.True(t, upsert(newNode(
		"underlay-1", "cluster-1", addressing.NodeInternalIP, "192.0.2.1",
	)))
	require.True(t, upsert(newNode(
		"underlay-2", "cluster-2", addressing.NodeInternalIP, "192.0.2.1",
	)))
	requireNode("cluster-1/underlay-1")
	requireNode("cluster-2/underlay-2")
}

func TestWriterProtectsOnlyLocalNodeIPs(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)
	local := &Node{
		Node: types.Node{
			Name:   "local",
			Source: source.Local,
			IPAddresses: []types.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("192.0.2.1")},
				{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("10.0.0.2")},
			},
			IPv4HealthIP:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")),
			IPv4IngressIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		},
		Local: &LocalNodeInfo{},
	}
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()

	upsert := func(n *types.Node) bool {
		txn = db.WriteTxn(nodes)
		defer txn.Commit()
		return w.Upsert(txn, n)
	}
	newNode := func(name string, addressType addressing.AddressType, address string) *types.Node {
		return &types.Node{
			Name:   name,
			Source: source.Kubernetes,
			IPAddresses: []types.Address{{
				Type: addressType,
				IP:   net.ParseIP(address),
			}},
		}
	}
	requireNode := func(name string) *Node {
		n, _, found := nodes.Get(db.ReadTxn(), NodeByName(name))
		require.True(t, found, name)
		return n
	}

	// Internal and external IPs are protected regardless of whether the local
	// and remote address types match. IPv4 representations are normalized.
	internalConflict := newNode("internal-conflict", addressing.NodeInternalIP, "10.0.0.1")
	internalConflict.IPAddresses[0].IP = net.IP{10, 0, 0, 1}
	require.False(t, upsert(internalConflict))
	require.False(t, upsert(newNode(
		"external-conflict", addressing.NodeInternalIP, "192.0.2.1",
	)))

	// Cilium internal, health, and ingress addresses do not participate in
	// local-node protection, even when the raw address is shared.
	require.True(t, upsert(newNode(
		"cilium-internal", addressing.NodeCiliumInternalIP, "10.0.0.2",
	)))
	require.True(t, upsert(newNode(
		"local-health", addressing.NodeInternalIP, "10.0.0.3",
	)))
	require.True(t, upsert(newNode(
		"local-ingress", addressing.NodeExternalIP, "10.0.0.4",
	)))
	auxiliary := &types.Node{
		Name:          "remote-auxiliary",
		Source:        source.CustomResource,
		IPv4HealthIP:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		IPv4IngressIP: iputil.AddrFrom(netip.MustParseAddr("192.0.2.1")),
	}
	require.True(t, upsert(auxiliary))

	// A rejected update leaves the previously accepted version in place.
	require.True(t, upsert(newNode(
		"existing", addressing.NodeInternalIP, "198.51.100.1",
	)))
	update := newNode("existing", addressing.NodeInternalIP, "10.0.0.1")
	update.Labels = map[string]string{"updated": "true"}
	require.False(t, upsert(update))
	existing := requireNode("existing")
	require.Equal(t, "198.51.100.1", existing.IPAddresses[0].ToString())
	require.Empty(t, existing.Labels)
}

func TestWriterProtectsLocalNodeCIDRs(t *testing.T) {
	db := statedb.New()
	nodes, err := NewNodeTable(db)
	require.NoError(t, err)
	w := NewWriter(hivetest.Logger(t), db, nodes)

	local := &Node{
		Node: types.Node{
			Name:   "local",
			Source: source.Local,
			IPAddresses: []types.Address{
				{Type: addressing.NodeInternalIP, IP: net.ParseIP("192.0.2.1")},
				{Type: addressing.NodeExternalIP, IP: net.ParseIP("2001:db8::1")},
				{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("198.51.100.1")},
			},
			IPv4AllocCIDR: types.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			IPv4SecondaryAllocCIDRs: []types.Prefix{
				types.PrefixFrom(netip.MustParsePrefix("10.1.0.0/24")),
			},
			IPv6AllocCIDR: types.PrefixFrom(netip.MustParsePrefix("fd00::/64")),
			IPv6SecondaryAllocCIDRs: []types.Prefix{
				types.PrefixFrom(netip.MustParsePrefix("fd01::/64")),
			},
		},
		Local: &LocalNodeInfo{},
	}
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()

	tests := []struct {
		name      string
		cidr      string
		secondary bool
		conflict  bool
	}{
		{"within IPv4 primary CIDR", "10.0.0.128/25", false, true},
		{"contains IPv4 primary CIDR", "10.0.0.0/16", false, true},
		{"overlaps IPv4 secondary CIDR", "10.1.0.128/25", true, true},
		{"within IPv6 primary CIDR", "fd00::/80", false, true},
		{"contains IPv6 secondary CIDR", "fd01::/48", true, true},
		{"contains local internal IP", "192.0.2.0/24", false, true},
		{"contains local external IP", "2001:db8::/64", false, true},
		{"contains local Cilium internal IP", "198.51.100.0/24", false, false},
		{"does not overlap local node", "203.0.113.0/24", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tt.cidr)
			remote := &types.Node{Name: tt.name, Source: source.Kubernetes}
			switch {
			case prefix.Addr().Is4() && tt.secondary:
				remote.IPv4SecondaryAllocCIDRs = []types.Prefix{types.PrefixFrom(prefix)}
			case prefix.Addr().Is4():
				remote.IPv4AllocCIDR = types.PrefixFrom(prefix)
			case tt.secondary:
				remote.IPv6SecondaryAllocCIDRs = []types.Prefix{types.PrefixFrom(prefix)}
			default:
				remote.IPv6AllocCIDR = types.PrefixFrom(prefix)
			}

			txn := db.WriteTxn(nodes)
			changed := w.Upsert(txn, remote)
			txn.Commit()
			require.Equal(t, !tt.conflict, changed)

			_, _, found := nodes.Get(db.ReadTxn(), NodeByName(remote.Name))
			require.Equal(t, !tt.conflict, found)
		})
	}
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
