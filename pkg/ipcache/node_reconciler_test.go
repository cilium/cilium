// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
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
}

func (m *metadataBatchMock) UpsertMetadataBatch(updates ...MU) uint64 {
	m.upserts = append(m.upserts, append([]MU(nil), updates...))
	return 0
}

func (m *metadataBatchMock) RemoveMetadataBatch(updates ...MU) uint64 {
	m.removals = append(m.removals, append([]MU(nil), updates...))
	return 0
}

func (*metadataBatchMock) WaitForRevision(context.Context, uint64) error {
	return nil
}

func newTestNodeReconcilerOps(
	t *testing.T,
	config *option.DaemonConfig,
	wgConfig fakewireguard.Config,
) (*nodeReconcilerOps, *metadataBatchMock, *statedb.DB, statedb.RWTable[*node.Node]) {
	t.Helper()
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)
	metadata := &metadataBatchMock{}
	return &nodeReconcilerOps{
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

func TestNodeReconcilerMetadataLifecycle(t *testing.T) {
	ops, metadata, db, _ := newTestNodeReconcilerOps(
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
		IPv4IngressIP: net.ParseIP("10.0.0.5"),
		IPv6IngressIP: net.ParseIP("f00d::5"),
		EncryptionKey: 42,
	}}

	require.NoError(t, ops.Update(context.Background(), db.ReadTxn(), 0, n))
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

	updated := n.DeepCopy()
	updated.IPAddresses = updated.IPAddresses[:2]
	updated.IPv4SecondaryAllocCIDRs = nil
	updated.IPv6SecondaryAllocCIDRs = nil
	require.NoError(t, ops.Update(context.Background(), db.ReadTxn(), 0, updated))
	require.Len(t, metadata.removals, 1)
	removed := updatesByPrefix(metadata.removals[0])
	require.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("f00d::1/128"),
		netip.MustParsePrefix("192.168.10.0/28"),
		netip.MustParsePrefix("cafe::/96"),
	}, mapKeys(removed))

	require.NoError(t, ops.Delete(context.Background(), db.ReadTxn(), 0, updated))
	require.Len(t, metadata.removals, 2)
	require.ElementsMatch(t,
		mapKeys(updatesByPrefix(metadata.upserts[1])),
		mapKeys(updatesByPrefix(metadata.removals[1])),
	)
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

func TestNodeReconcilerNodeEncryption(t *testing.T) {
	ops, _, db, nodes := newTestNodeReconcilerOps(
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
	desired := ops.metadataForNode(db.ReadTxn(), remote)
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
	desired = ops.metadataForNode(db.ReadTxn(), remote)
	require.Equal(t, ipcacheTypes.EncryptKey(42), metadataValue[ipcacheTypes.EncryptKey](
		t,
		desired[cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.2/32"))],
	))

	ops.wgConfig = fakewireguard.Config{EnableWireguard: true}
	desired = ops.metadataForNode(db.ReadTxn(), remote)
	require.Equal(t, ipcacheTypes.EncryptKey(0xff), metadataValue[ipcacheTypes.EncryptKey](
		t,
		desired[cmtypes.PrefixClusterFrom(netip.MustParsePrefix("10.0.0.3/32"))],
	))
}

func TestNodeReconcilerNodeIdentityLabels(t *testing.T) {
	require.NoError(t, labelsfilter.ParseLabelPrefixCfg(
		hivetest.Logger(t),
		nil,
		nil,
		"",
	))
	ops, _, _, _ := newTestNodeReconcilerOps(
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
	require.True(t, want.Equals(ops.nodeIdentityLabels(local)))

	remote := local.DeepCopy()
	remote.Name = "remote"
	remote.Local = nil
	want = labels.NewFrom(labels.LabelRemoteNode)
	want.MergeLabels(labels.Map2Labels(remote.Labels, labels.LabelSourceNode))
	want.MergeLabels(labels.Map2Labels(map[string]string{
		"io.cilium.k8s.policy.cluster": "cluster1",
	}, labels.LabelSourceK8s))
	require.True(t, want.Equals(ops.nodeIdentityLabels(remote)))
}

func TestNodeReconcilerInvalidatesRemoteNodes(t *testing.T) {
	ops, _, db, nodes := newTestNodeReconcilerOps(
		t,
		&option.DaemonConfig{EncryptNode: true},
		fakewireguard.Config{},
	)
	local := &node.Node{
		Node:  nodeTypes.Node{Name: "local", Source: source.Local},
		Local: &node.LocalNodeInfo{OptOutNodeEncryption: true},
	}
	local.Statuses = local.Statuses.Set(nodeReconcilerName, reconciler.StatusDone())
	remote := &node.Node{Node: nodeTypes.Node{Name: "remote"}}
	remote.Statuses = remote.Statuses.Set(nodeReconcilerName, reconciler.StatusDone())
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Insert(txn, local)
	require.NoError(t, err)
	_, _, err = nodes.Insert(txn, remote)
	require.NoError(t, err)
	txn.Commit()

	previous := false
	ops.localOptOut = &previous
	require.NoError(t, ops.Update(context.Background(), db.ReadTxn(), 0, local))

	remote, _, found := nodes.Get(db.ReadTxn(), node.NodeByName(remote.Fullname()))
	require.True(t, found)
	require.Equal(t, reconciler.StatusKindPending,
		remote.Statuses.Get(nodeReconcilerName).Kind,
	)
	local, _, found = nodes.Get(db.ReadTxn(), node.LocalNodeQuery)
	require.True(t, found)
	require.Equal(t, reconciler.StatusKindDone,
		local.Statuses.Get(nodeReconcilerName).Kind,
	)
}
