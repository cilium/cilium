// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
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
