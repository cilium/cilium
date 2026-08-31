// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ip"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

type metadataBatchMock struct {
	upserts  [][]MU
	removals [][]MU
	notify   chan struct{}
}

func (m *metadataBatchMock) UpsertMetadataBatch(updates ...MU) uint64 {
	m.upserts = append(m.upserts, append([]MU(nil), updates...))
	if m.notify != nil {
		m.notify <- struct{}{}
	}
	return 0
}

func (m *metadataBatchMock) RemoveMetadataBatch(updates ...MU) uint64 {
	m.removals = append(m.removals, append([]MU(nil), updates...))
	if m.notify != nil {
		m.notify <- struct{}{}
	}
	return 0
}

type testHealth struct{}

func (testHealth) OK(string)                     {}
func (testHealth) Stopped(string)                {}
func (testHealth) Degraded(string, error)        {}
func (h testHealth) NewScope(string) cell.Health { return h }
func (testHealth) Close()                        {}

func TestNodeObserverWaitsForLocalNodeInitialization(t *testing.T) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)
	metadata := &metadataBatchMock{notify: make(chan struct{}, 1)}
	observer := &nodeObserver{
		db:          db,
		nodes:       nodes,
		ipcache:     metadata,
		config:      &option.DaemonConfig{},
		clusterInfo: cmtypes.DefaultClusterInfo,
		underlay:    tunnel.IPv4,
		wgConfig:    fakewireguard.Config{},
		lastApplied: map[nodeTypes.Identity]map[cmtypes.PrefixCluster]MU{},
	}

	txn := db.WriteTxn(nodes)
	initDone := nodes.RegisterInitializer(txn, node.LocalNodeTableInitializerName)
	_, _, err = nodes.Insert(txn, &node.Node{Node: nodeTypes.Node{
		Name: "remote",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
	}})
	require.NoError(t, err)
	txn.Commit()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- observer.run(ctx, testHealth{}) }()

	select {
	case <-metadata.notify:
		require.FailNow(t, "observer ran before local node initialization")
	case <-time.After(20 * time.Millisecond):
	}

	txn = db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, &node.Node{
		Node:  nodeTypes.Node{Name: "local", Source: source.Local},
		Local: &node.LocalNodeInfo{},
	})
	require.NoError(t, err)
	initDone(txn)
	txn.Commit()

	select {
	case <-metadata.notify:
	case <-time.After(time.Second):
		require.FailNow(t, "observer did not process initial node snapshot")
	}
	cancel()
	require.NoError(t, <-done)
}

func newTestNodeObserver(
	t *testing.T,
	config *option.DaemonConfig,
	wgConfig fakewireguard.Config,
) (*nodeObserver, *metadataBatchMock, *statedb.DB, statedb.RWTable[*node.Node]) {
	t.Helper()
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)
	metadata := &metadataBatchMock{}
	return &nodeObserver{
		db:          db,
		nodes:       nodes,
		ipcache:     metadata,
		config:      config,
		clusterInfo: cmtypes.DefaultClusterInfo,
		underlay:    tunnel.IPv4,
		wgConfig:    wgConfig,
		lastApplied: map[nodeTypes.Identity]map[cmtypes.PrefixCluster]MU{},
	}, metadata, db, nodes
}

func applyNodeUpdate(
	t *testing.T,
	observer *nodeObserver,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	n *node.Node,
) {
	t.Helper()
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Insert(txn, n)
	require.NoError(t, err)
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{{Object: n}})
}

func applyNodeDelete(
	t *testing.T,
	observer *nodeObserver,
	db *statedb.DB,
	nodes statedb.RWTable[*node.Node],
	n *node.Node,
) {
	t.Helper()
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Delete(txn, n)
	require.NoError(t, err)
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{{
		Object:  n,
		Deleted: true,
	}})
}

func updatesByPrefix(updates []MU) map[netip.Prefix]MU {
	byPrefix := make(map[netip.Prefix]MU, len(updates))
	for _, update := range updates {
		byPrefix[update.Prefix.AsPrefix()] = update
	}
	return byPrefix
}

func metadataValue[T any](t *testing.T, update MU) T {
	t.Helper()
	for _, metadata := range update.Metadata {
		if value, ok := metadata.(T); ok {
			return value
		}
	}
	var zero T
	require.FailNow(t, "metadata type not found", "%T", zero)
	return zero
}

func TestNodeObserverMetadataLifecycle(t *testing.T) {
	observer, metadata, db, nodes := newTestNodeObserver(
		t,
		&option.DaemonConfig{},
		fakewireguard.Config{},
	)
	n := &node.Node{Node: nodeTypes.Node{
		Name:    "node1",
		Cluster: "cluster1",
		Source:  source.Kubernetes,
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
		IPv4AllocCIDR: nodeTypes.PrefixFrom(
			netip.MustParsePrefix("10.0.0.0/24"),
		),
		IPv4SecondaryAllocCIDRs: []nodeTypes.Prefix{nodeTypes.PrefixFrom(
			netip.MustParsePrefix("192.168.10.0/28"),
		)},
		IPv6AllocCIDR: nodeTypes.PrefixFrom(
			netip.MustParsePrefix("f00d::/96"),
		),
		IPv6SecondaryAllocCIDRs: []nodeTypes.Prefix{nodeTypes.PrefixFrom(
			netip.MustParsePrefix("cafe::/96"),
		)},
		IPv4HealthIP:  ip.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		IPv6HealthIP:  ip.AddrFrom(netip.MustParseAddr("f00d::4")),
		IPv4IngressIP: ip.AddrFrom(netip.MustParseAddr("10.0.0.5")),
		IPv6IngressIP: ip.AddrFrom(netip.MustParseAddr("f00d::5")),
		EncryptionKey: 42,
	}}

	applyNodeUpdate(t, observer, db, nodes, n)
	require.Len(t, metadata.upserts, 1)
	upserts := updatesByPrefix(metadata.upserts[0])
	require.Len(t, upserts, 11)

	nodeAddress := upserts[netip.MustParsePrefix("1.1.1.1/32")]
	require.Equal(t, source.Kubernetes, nodeAddress.Source)
	require.Equal(t,
		ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindNode, "cluster1", "node1"),
		nodeAddress.Resource,
	)
	require.True(t, labels.LabelRemoteNode.Equals(
		metadataValue[labels.Labels](t, nodeAddress),
	))
	require.Equal(t, netip.MustParseAddr("10.0.0.2"),
		metadataValue[ipcacheTypes.TunnelPeer](t, nodeAddress).Addr,
	)
	require.Equal(t, uint8(ipcacheTypes.FlagRemoteCluster),
		metadataValue[ipcacheTypes.EndpointFlags](t, nodeAddress).Uint8(),
	)

	podCIDR := upserts[netip.MustParsePrefix("10.0.0.0/24")]
	require.Equal(t, ipcacheTypes.EncryptKey(42),
		metadataValue[ipcacheTypes.EncryptKey](t, podCIDR),
	)
	require.True(t, worldLabelForPrefix(podCIDR.Prefix.AsPrefix()).Equals(
		metadataValue[labels.Labels](t, podCIDR),
	))

	health := upserts[netip.MustParsePrefix("10.0.0.4/32")]
	require.True(t, labels.LabelHealth.Equals(
		metadataValue[labels.Labels](t, health),
	))
	require.Equal(t, ipcacheTypes.EncryptKey(42),
		metadataValue[ipcacheTypes.EncryptKey](t, health),
	)
	ingress := upserts[netip.MustParsePrefix("f00d::5/128")]
	require.True(t, labels.LabelIngress.Equals(
		metadataValue[labels.Labels](t, ingress),
	))

	// Status-only table writes do not change the derived metadata.
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{{Object: n}})
	require.Len(t, metadata.upserts, 1)

	updated := n.DeepCopy()
	updated.IPAddresses = updated.IPAddresses[:2]
	updated.IPv4SecondaryAllocCIDRs = nil
	updated.IPv6SecondaryAllocCIDRs = nil
	applyNodeUpdate(t, observer, db, nodes, updated)
	require.Len(t, metadata.removals, 1)
	removed := updatesByPrefix(metadata.removals[0])
	require.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("f00d::1/128"),
		netip.MustParsePrefix("192.168.10.0/28"),
		netip.MustParsePrefix("cafe::/96"),
	}, mapKeys(removed))

	applyNodeDelete(t, observer, db, nodes, updated)
	require.Len(t, metadata.removals, 2)
	require.ElementsMatch(t,
		mapKeys(updatesByPrefix(metadata.upserts[1])),
		mapKeys(updatesByPrefix(metadata.removals[1])),
	)
}

func TestNodeObserverBatchesChanges(t *testing.T) {
	observer, metadata, db, table := newTestNodeObserver(
		t,
		&option.DaemonConfig{},
		fakewireguard.Config{},
	)
	nodes := []*node.Node{
		{Node: nodeTypes.Node{
			Name:    "node1",
			Cluster: "cluster1",
			Source:  source.Kubernetes,
			IPAddresses: []nodeTypes.Address{{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			}},
		}},
		{Node: nodeTypes.Node{
			Name:    "node2",
			Cluster: "cluster1",
			Source:  source.Kubernetes,
			IPAddresses: []nodeTypes.Address{{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.2"),
			}},
		}},
	}
	txn := db.WriteTxn(table)
	for _, n := range nodes {
		_, _, err := table.Insert(txn, n)
		require.NoError(t, err)
	}
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{
		{Object: nodes[0]},
		{Object: nodes[1]},
	})
	require.Len(t, metadata.upserts, 1)
	require.Len(t, metadata.upserts[0], 2)

	txn = db.WriteTxn(table)
	for _, n := range nodes {
		_, _, err := table.Delete(txn, n)
		require.NoError(t, err)
	}
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{
		{Object: nodes[0], Deleted: true},
		{Object: nodes[1], Deleted: true},
	})
	require.Len(t, metadata.removals, 1)
	require.Len(t, metadata.removals[0], 2)
}

func TestNodeObserverCollapsesIntermediateChanges(t *testing.T) {
	observer, metadata, db, table := newTestNodeObserver(
		t,
		&option.DaemonConfig{},
		fakewireguard.Config{},
	)
	old := &node.Node{Node: nodeTypes.Node{
		Name: "node1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		}},
	}}
	updated := old.DeepCopy()
	updated.IPAddresses[0].IP = net.ParseIP("10.0.0.2")

	txn := db.WriteTxn(table)
	_, _, err := table.Insert(txn, updated)
	require.NoError(t, err)
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{
		{Object: old},
		{Object: updated},
	})

	require.Len(t, metadata.upserts, 1)
	require.Len(t, metadata.upserts[0], 1)
	require.Equal(t, netip.MustParsePrefix("10.0.0.2/32"),
		metadata.upserts[0][0].Prefix.AsPrefix())
}

func mapKeys(entries map[netip.Prefix]MU) []netip.Prefix {
	keys := make([]netip.Prefix, 0, len(entries))
	for prefix := range entries {
		keys = append(keys, prefix)
	}
	return keys
}

func TestMetadataRemovalsForRetainedPrefix(t *testing.T) {
	prefix := cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.1/32"))
	flags := ipcacheTypes.EndpointFlags{}
	flags.SetRemoteCluster(true)
	old := map[cmtypes.PrefixCluster]MU{
		prefix: {
			Prefix: prefix,
			Metadata: []IPMetadata{
				labels.LabelRemoteNode,
				ipcacheTypes.TunnelPeer{},
				ipcacheTypes.EncryptKey(0),
				flags,
			},
		},
	}
	desired := map[cmtypes.PrefixCluster]MU{
		prefix: {
			Prefix: prefix,
			Metadata: []IPMetadata{
				labels.LabelHealth,
				ipcacheTypes.TunnelPeer{},
				ipcacheTypes.EncryptKey(0),
			},
		},
	}

	removals := metadataRemovals(old, desired)
	require.Len(t, removals, 1)
	require.Equal(t, []IPMetadata{flags}, removals[0].Metadata)
}

func TestNodeObserverNodeEncryption(t *testing.T) {
	observer, _, db, nodes := newTestNodeObserver(
		t,
		&option.DaemonConfig{EncryptNode: true},
		fakewireguard.Config{},
	)
	local := &node.Node{
		Node:  nodeTypes.Node{Name: "local", Source: source.Local},
		Local: &node.LocalNodeInfo{OptOutNodeEncryption: true},
	}
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{{Object: local}})

	remote := &node.Node{Node: nodeTypes.Node{
		Name:          "remote",
		Cluster:       cmtypes.DefaultClusterInfo.Name,
		EncryptionKey: 42,
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		}},
		IPv4HealthIP: ip.AddrFrom(netip.MustParseAddr("10.0.0.3")),
	}}
	desired := observer.metadataForNode(remote)
	require.Equal(t, ipcacheTypes.EncryptKey(0), metadataValue[ipcacheTypes.EncryptKey](
		t,
		desired[cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.2/32"))],
	))
	require.Equal(t, ipcacheTypes.EncryptKey(42), metadataValue[ipcacheTypes.EncryptKey](
		t,
		desired[cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.3/32"))],
	))

	local = local.DeepCopy()
	local.Local.OptOutNodeEncryption = false
	txn = db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, local)
	require.NoError(t, err)
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{{Object: local}})
	desired = observer.metadataForNode(remote)
	require.Equal(t, ipcacheTypes.EncryptKey(42), metadataValue[ipcacheTypes.EncryptKey](
		t,
		desired[cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.2/32"))],
	))

	observer.wgConfig = fakewireguard.Config{EnableWireguard: true}
	desired = observer.metadataForNode(remote)
	require.Equal(t, ipcacheTypes.EncryptKey(0xff), metadataValue[ipcacheTypes.EncryptKey](
		t,
		desired[cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.3/32"))],
	))
}

func TestNodeObserverNodeIdentityLabels(t *testing.T) {
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(
		hivetest.Logger(t),
		nil,
		nil,
		"",
	))
	observer, _, _, _ := newTestNodeObserver(
		t,
		&option.DaemonConfig{
			EnableIPv4:               true,
			EnableNodeSelectorLabels: true,
			PolicyCIDRMatchMode:      []string{"nodes"},
		},
		fakewireguard.Config{},
	)

	local := &node.Node{
		Node: nodeTypes.Node{
			Name:    "local",
			Cluster: "cluster1",
			Labels:  map[string]string{"role": "worker"},
			IPAddresses: []nodeTypes.Address{{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			}},
		},
		Local: &node.LocalNodeInfo{},
	}
	want := labels.NewFrom(labels.LabelHost)
	want.MergeLabels(labels.Map2Labels(local.Labels, labels.LabelSourceNode))
	want.MergeLabels(labels.Map2Labels(map[string]string{
		"io.cilium.k8s.policy.cluster": "cluster1",
	}, labels.LabelSourceK8s))
	want.MergeLabels(labels.GetCIDRLabels(netip.MustParsePrefix("10.0.0.1/32")))
	require.True(t, want.Equals(observer.nodeIdentityLabels(local)))

	remote := local.DeepCopy()
	remote.Name = "remote"
	remote.Local = nil
	want = labels.NewFrom(labels.LabelRemoteNode)
	want.MergeLabels(labels.Map2Labels(remote.Labels, labels.LabelSourceNode))
	want.MergeLabels(labels.Map2Labels(map[string]string{
		"io.cilium.k8s.policy.cluster": "cluster1",
	}, labels.LabelSourceK8s))
	require.True(t, want.Equals(observer.nodeIdentityLabels(remote)))
}

func TestNodeObserverRecomputesRemoteNodesOnLocalEncryptionChange(t *testing.T) {
	observer, metadata, db, nodes := newTestNodeObserver(
		t,
		&option.DaemonConfig{EncryptNode: true},
		fakewireguard.Config{},
	)
	local := &node.Node{
		Node:  nodeTypes.Node{Name: "local", Source: source.Local},
		Local: &node.LocalNodeInfo{OptOutNodeEncryption: true},
	}
	remote := &node.Node{Node: nodeTypes.Node{
		Name:          "remote",
		EncryptionKey: 42,
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		}},
	}}
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Insert(txn, local)
	require.NoError(t, err)
	_, _, err = nodes.Insert(txn, remote)
	require.NoError(t, err)
	txn.Commit()
	observer.apply(db.ReadTxn(), []statedb.Change[*node.Node]{
		{Object: local},
		{Object: remote},
	})

	local = local.DeepCopy()
	local.Local.OptOutNodeEncryption = false
	applyNodeUpdate(t, observer, db, nodes, local)

	require.Len(t, metadata.upserts, 2)
	remoteAddress := updatesByPrefix(metadata.upserts[1])[netip.MustParsePrefix("10.0.0.2/32")]
	require.Equal(t, ipcacheTypes.EncryptKey(42),
		metadataValue[ipcacheTypes.EncryptKey](t, remoteAddress),
	)
}
