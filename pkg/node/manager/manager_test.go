// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/identity"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	fakewireguard "github.com/cilium/cilium/pkg/wireguard/fake"
)

type nodeEvent struct {
	event    string
	prefix   netip.Prefix
	metadata ipcache.IPMetadata
}

func testClusterSizeDependantInterval(interval time.Duration) time.Duration {
	return interval
}

type ipcacheMock struct {
	events chan nodeEvent
}

func newIPcacheMock() *ipcacheMock {
	return &ipcacheMock{
		events: make(chan nodeEvent, 1024),
	}
}

func AddrOrPrefixToIP(ip string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(ip)
	if err != nil {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return netip.Prefix{}, err
		}
		return addr.Prefix(prefix.Bits())
	}

	return prefix, err
}

func (i *ipcacheMock) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity, aux ...ipcache.IPMetadata) (bool, error) {
	addr, err := AddrOrPrefixToIP(ip)
	if err != nil {
		i.events <- nodeEvent{fmt.Sprintf("upsert failed: %s", err), addr, aux}
		return false, err
	}
	i.events <- nodeEvent{"upsert", addr, aux}
	return false, nil
}

func (i *ipcacheMock) Delete(ip string, source source.Source, aux ...ipcache.IPMetadata) bool {
	addr, err := AddrOrPrefixToIP(ip)
	if err != nil {
		i.events <- nodeEvent{fmt.Sprintf("delete failed: %s", err), addr, aux}
		return false
	}
	i.events <- nodeEvent{"delete", addr, aux}
	return false
}

func (i *ipcacheMock) GetMetadataSourceByPrefix(prefix cmtypes.PrefixCluster) source.Source {
	return source.Unspec
}

func (i *ipcacheMock) UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
	i.Upsert(prefix.String(), nil, 0, nil, ipcache.Identity{}, aux...)
}

func (i *ipcacheMock) RemoveMetadata(prefix cmtypes.PrefixCluster, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
	i.Delete(prefix.String(), source.CustomResource, aux...)
}

func (i *ipcacheMock) UpsertMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	for _, update := range updates {
		i.UpsertMetadata(update.Prefix, update.Source, update.Resource, update.Metadata)
	}
	return 0
}

func (i *ipcacheMock) RemoveMetadataBatch(updates ...ipcache.MU) (revision uint64) {
	for _, update := range updates {
		i.RemoveMetadata(update.Prefix, update.Resource, update.Metadata)
	}
	return 0
}

func TestNodeLifecycle(t *testing.T) {
	logger := hivetest.Logger(t)

	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)

	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)

	n1 := nodeTypes.Node{
		Name: "node1", Cluster: "c1", IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
			},
		},
		Source: source.Unspec,
	}
	mngr.NodeUpdated(n1)

	n2 := nodeTypes.Node{
		Name: "node2", Cluster: "c1", IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
			},
		},
		Source: source.Unspec,
	}
	mngr.NodeUpdated(n2)

	nodes := mngr.GetNodes()
	n, ok := nodes[n1.Identity()]
	require.True(t, ok)
	require.Equal(t, n1, n)

	mngr.NodeDeleted(n1)
	nodes = mngr.GetNodes()
	_, ok = nodes[n1.Identity()]
	require.False(t, ok)

	err = mngr.Stop(context.TODO())
	require.NoError(t, err)
}

func TestNodeLabels(t *testing.T) {
	logger := hivetest.Logger(t)

	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()

	nodeLabels := map[string]string{
		"test-label":  "test-value",
		"other-label": "other-value",
	}
	nodeTypes.SetName("localNode")
	nLocal := nodeTypes.Node{
		Name:    "localNode",
		Cluster: "default",
		Labels:  nodeLabels,
		Source:  source.Local,
	}
	nRemote := nodeTypes.Node{
		Name:    "remoteNode",
		Cluster: "default",
		Labels:  nodeLabels,
		Source:  source.Unspec,
	}

	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)

	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	mngr.NodeUpdated(nRemote)

	tests := []struct {
		name               string
		node               nodeTypes.Node
		nodeSelectorLabels bool
		nodeLabelPrefixes  []string
		setupWanted        func() labels.Labels
	}{{
		name:               "Local node with node selector labels enabled",
		node:               nLocal,
		nodeSelectorLabels: true,
		setupWanted: func() labels.Labels {
			want := labels.NewFrom(labels.LabelHost)
			want.MergeLabels(labels.Map2Labels(nodeLabels, labels.LabelSourceNode))
			want.MergeLabels(labels.Map2Labels(map[string]string{
				"io.cilium.k8s.policy.cluster": "default",
			}, labels.LabelSourceK8s))
			return want
		},
	}, {
		name:               "Local node with node selector labels disabled",
		node:               nLocal,
		nodeSelectorLabels: false,
		setupWanted: func() labels.Labels {
			return labels.NewFrom(labels.LabelHost)
		},
	}, {
		name:               "Remote node with node selector labels enabled",
		node:               nRemote,
		nodeSelectorLabels: true,
		setupWanted: func() labels.Labels {
			want := labels.NewFrom(labels.LabelRemoteNode)
			want.MergeLabels(labels.Map2Labels(nodeLabels, labels.LabelSourceNode))
			want.MergeLabels(labels.Map2Labels(map[string]string{
				"io.cilium.k8s.policy.cluster": "default",
			}, labels.LabelSourceK8s))
			return want
		},
	}, {
		name:               "Remote node with node selector labels disabled",
		node:               nRemote,
		nodeSelectorLabels: false,
		setupWanted: func() labels.Labels {
			return labels.NewFrom(labels.LabelRemoteNode)
		},
	}, {
		name:               "Remote node with node selector labels enabled and filtered labels",
		node:               nRemote,
		nodeSelectorLabels: true,
		nodeLabelPrefixes:  []string{"node:test-label"},
		setupWanted: func() labels.Labels {
			want := labels.NewFrom(labels.LabelRemoteNode)
			want.MergeLabels(labels.Map2Labels(map[string]string{
				"test-label": "test-value",
			}, labels.LabelSourceNode))
			want.MergeLabels(labels.Map2Labels(map[string]string{
				"io.cilium.k8s.policy.cluster": "default",
			}, labels.LabelSourceK8s))
			return want
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, labelsfilter.ParseLabelPrefixCfg(logger, nil, tt.nodeLabelPrefixes, ""))
			option.Config.EnableNodeSelectorLabels = tt.nodeSelectorLabels
			option.Config.ClusterName = cmtypes.DefaultClusterInfo.Name
			got := mngr.nodeIdentityLabels(tt.node)
			want := tt.setupWanted()
			assert.True(t, want.Equals(got), "Mismatched labels: want=%v got=%v", want, got)
		})
	}
}

func TestNodeCIDRLabels(t *testing.T) {
	oldNodeSelectorLabels := option.Config.EnableNodeSelectorLabels
	oldPolicyCIDRMatchMode := option.Config.PolicyCIDRMatchMode
	oldClusterName := option.Config.ClusterName
	t.Cleanup(func() {
		option.Config.EnableNodeSelectorLabels = oldNodeSelectorLabels
		option.Config.PolicyCIDRMatchMode = oldPolicyCIDRMatchMode
		option.Config.ClusterName = oldClusterName
	})
	option.Config.EnableNodeSelectorLabels = false
	option.Config.PolicyCIDRMatchMode = []string{}
	option.Config.ClusterName = "default"

	logger := hivetest.Logger(t)
	labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, "")

	h, _ := cell.NewSimpleHealth()
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           t.Context(),
		Logger:            logger,
		IdentityAllocator: testidentity.NewMockIdentityAllocator(nil),
		IdentityUpdater:   &mockUpdater{},
	})

	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipc, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)

	nodeTypes.SetName("localNode")
	nLocal := nodeTypes.Node{
		Name:    "localNode",
		Cluster: option.Config.ClusterName,
		Labels:  map[string]string{"a": "b"},
		Source:  source.Local,
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		}},
	}
	nRemote := nodeTypes.Node{
		Name:    "remoteNode",
		Cluster: option.Config.ClusterName,
		Labels:  map[string]string{"a": "c"},
		Source:  source.Kubernetes,
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
		}},
	}

	setIPLabels := func(pfx string, lbls ...string) {
		var rev uint64
		if len(lbls) > 0 {
			rev = ipc.UpsertMetadataBatch(ipcache.MU{
				Prefix:   cmtypes.MustParsePrefixCluster(pfx),
				Source:   source.CustomResource,
				Resource: "dummy",
				Metadata: []ipcache.IPMetadata{labels.ParseLabels(lbls...)},
			})
		} else {
			rev = ipc.RemoveMetadataBatch(ipcache.MU{
				Prefix:   cmtypes.MustParsePrefixCluster(pfx),
				Source:   source.CustomResource,
				Resource: "dummy",
				Metadata: []ipcache.IPMetadata{labels.Labels{}},
			})
		}
		ipc.WaitForRevision(t.Context(), rev)
	}

	dummyIP := netip.MustParseAddr("100.0.0.1")

	// updateAndCheck commits the node update to the
	updateAndCheck := func(n nodeTypes.Node, wantLbls labels.Labels, wantNID identity.NumericIdentity) {
		t.Helper()
		mngr.NodeUpdated(n)
		// make a dummy ipcache update so we're sure the metadata resolver has run.
		// This is to prevent test flakes.
		setIPLabels(dummyIP.String()+"/32", "reserved:ingress")
		dummyIP = dummyIP.Next()

		ip := netip.MustParseAddr(n.IPAddresses[0].IP.String())
		ipcID, ok := ipc.LookupSecIDByIP(ip)
		require.True(t, ok)
		if wantNID != 0 {
			require.Equal(t, wantNID, ipcID.ID)
		}
		secID := ipc.IdentityAllocator.LookupIdentityByID(t.Context(), ipcID.ID)
		require.NotNil(t, secID)
		require.Equal(t, wantLbls, secID.Labels)
	}

	// Standard case: nodes do not have non-reserved labels.
	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
	), identity.ReservedIdentityRemoteNode)

	// Set both nodes to be kube-apiserver
	setIPLabels("10.0.0.1/32", "reserved:kube-apiserver")
	setIPLabels("10.0.0.2/32", "reserved:kube-apiserver")

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"reserved:kube-apiserver",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
	), identity.ReservedIdentityKubeAPIServer)

	// Enable CIDR selection, see that nothing changes
	option.Config.PolicyCIDRMatchMode = []string{"nodes"}

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"reserved:kube-apiserver",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
	), identity.ReservedIdentityKubeAPIServer)

	// Add a CIDR selector that covers both nodes
	setIPLabels("10.0.0.0/24", "cidr:10.0.0.0/24")

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"reserved:kube-apiserver",
		"cidr:10.0.0.0/24",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
		"cidr:10.0.0.0/24",
	), identity.IdentityScopeRemoteNode)

	// Add a CIDR selector that selects only one node
	setIPLabels("10.0.0.2/31", "cidr:10.0.0.2/31")

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"reserved:kube-apiserver",
		"cidr:10.0.0.0/24",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
		"cidr:10.0.0.2/31",
	), identity.IdentityScopeRemoteNode+1)

	// Remove the /24 selector
	setIPLabels("10.0.0.0/24")

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"reserved:kube-apiserver",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
		"cidr:10.0.0.2/31",
	), identity.IdentityScopeRemoteNode+1)

	// add the /24 back, remove kube-apiserver from localhost
	setIPLabels("10.0.0.1/32")
	setIPLabels("10.0.0.0/24", "cidr:10.0.0.0/24")

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"cidr:10.0.0.0/24",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
		"cidr:10.0.0.2/31",
	), identity.IdentityScopeRemoteNode+1)

	// remove the /31, see that remote node was correctly updated.
	setIPLabels("10.0.0.2/31")

	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"cidr:10.0.0.0/24",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
		"cidr:10.0.0.0/24",
	), identity.IdentityScopeRemoteNode+2)

	// Enable node selector labels
	option.Config.EnableNodeSelectorLabels = true
	updateAndCheck(nLocal, labels.ParseLabels(
		"reserved:host",
		"node:a=b",
		"k8s:io.cilium.k8s.policy.cluster=default",
		"cidr:10.0.0.0/24",
	), identity.ReservedIdentityHost)

	updateAndCheck(nRemote, labels.ParseLabels(
		"reserved:remote-node",
		"reserved:kube-apiserver",
		"node:a=c",
		"k8s:io.cilium.k8s.policy.cluster=default",
		"cidr:10.0.0.0/24",
	), identity.IdentityScopeRemoteNode+3)
}

func TestMultipleSources(t *testing.T) {
	logger := hivetest.Logger(t)

	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1k8s := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Kubernetes, IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
	}}
	mngr.NodeUpdated(n1k8s)
	// agent can overwrite kubernetes
	n1agent := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Local, IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
	}}
	mngr.NodeUpdated(n1agent)
	// kubernetes cannot overwrite local node
	mngr.NodeUpdated(n1k8s)
	require.Equal(t, n1agent, mngr.GetNodes()[n1agent.Identity()])

	// delete from kubernetes, should not remove local node
	mngr.NodeDeleted(n1k8s)
	require.Equal(t, n1agent, mngr.GetNodes()[n1agent.Identity()])

	mngr.NodeDeleted(n1agent)
	_, found := mngr.GetNodes()[n1agent.Identity()]
	require.False(t, found)
}

func BenchmarkUpdateAndDeleteCycle(b *testing.B) {
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(b)
	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, nil, nil, fakewireguard.Config{}, nil, testClusterSizeDependantInterval)
	require.NoError(b, err)
	defer mngr.Stop(context.TODO())

	for i := 0; b.Loop(); i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeUpdated(n)
	}

	for i := 0; b.Loop(); i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeDeleted(n)
	}
	b.StopTimer()
}

func expectIPCacheUpdate(
	t *testing.T, ipcacheMock *ipcacheMock,
	eventType string, prefix netip.Prefix, metadata ...ipcache.IPMetadata,
) {
	t.Helper()

	select {
	case ev := <-ipcacheMock.events:
		require.Equal(t, eventType, ev.event)
		require.Equal(t, prefix, ev.prefix)
		if len(metadata) > 0 {
			// unpack outer metadata slice
			require.IsType(t, []ipcache.IPMetadata{}, ev.metadata)
			md := ev.metadata.([]ipcache.IPMetadata)

			require.ElementsMatch(t, metadata, md)
		}
	case <-time.After(5 * time.Second):
		t.Errorf("timeout while waiting for ipcache upsert for %s", prefix)
	}
}

func TestIpcache(t *testing.T) {
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.1"))},
			{Type: addressing.NodeInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2"))},
			{Type: addressing.NodeExternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("f00d::1"))},
		},

		IPv4AllocCIDR:           nodeTypes.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
		IPv4SecondaryAllocCIDRs: []nodeTypes.Prefix{nodeTypes.PrefixFrom(netip.MustParsePrefix("192.168.10.0/28"))},
		IPv6AllocCIDR:           nodeTypes.PrefixFrom(netip.MustParsePrefix("f00d::/96")),
		IPv6SecondaryAllocCIDRs: []nodeTypes.Prefix{nodeTypes.PrefixFrom(netip.MustParsePrefix("cafe::/96"))},
	}
	mngr.NodeUpdated(n1)

	// node IP addresses
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128))

	// node IPv4 allocation CIDRs
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("10.0.0.0/24"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("192.168.10.0/28"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)

	// node IPv6 allocation CIDRs
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("f00d::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("cafe::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	// Update node by removing ExternalIPs and secondary PodCIDRs
	n1 = *n1.DeepCopy()
	n1.IPAddresses = slices.DeleteFunc(n1.IPAddresses, func(address nodeTypes.Address) bool {
		return address.IP.Addr == netip.MustParseAddr("f00d::1")
	})
	n1.IPv4SecondaryAllocCIDRs = nil
	n1.IPv6SecondaryAllocCIDRs = nil
	mngr.NodeUpdated(n1)

	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32))
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("10.0.0.0/24"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("f00d::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)

	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.MustParsePrefix("192.168.10.0/28"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "delete", netip.MustParsePrefix("cafe::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)

	mngr.NodeDeleted(n1)

	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32))
	expectIPCacheUpdate(
		t, ipcacheMock, "delete", netip.MustParsePrefix("10.0.0.0/24"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.MustParsePrefix("f00d::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(0),
		},
	)

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func TestIpcacheHealthIP(t *testing.T) {
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.1"))},
		},
		IPv4HealthIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
		IPv6HealthIP: iputil.AddrFrom(netip.MustParseAddr("f00d::4")),
	}
	mngr.NodeUpdated(n1)

	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("10.0.0.4"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("f00d::4"), 128))

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("10.0.0.4"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("f00d::4"), 128))

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func TestNodeEncryption(t *testing.T) {
	logger := hivetest.Logger(t)

	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{
		EncryptNode: true,
	}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("1.1.1.1"))},
			{Type: addressing.NodeInternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2"))},
			{Type: addressing.NodeExternalIP, IP: iputil.AddrFrom(netip.MustParseAddr("f00d::1"))},
		},
		IPv4AllocCIDR:           nodeTypes.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
		IPv4SecondaryAllocCIDRs: []nodeTypes.Prefix{nodeTypes.PrefixFrom(netip.MustParsePrefix("192.168.10.0/28"))},
		IPv6AllocCIDR:           nodeTypes.PrefixFrom(netip.MustParsePrefix("f00d::/96")),
		IPv6SecondaryAllocCIDRs: []nodeTypes.Prefix{nodeTypes.PrefixFrom(netip.MustParsePrefix("cafe::/96"))},
		EncryptionKey:           42,
	}
	mngr.NodeUpdated(n1)

	// node IP addresses
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128))

	// node IPv4 allocation CIDRs
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("10.0.0.0/24"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("192.168.10.0/28"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)

	// node IPv6 allocation CIDRs
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("f00d::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "upsert", netip.MustParsePrefix("cafe::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	// node IP addresses
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128))

	// node IPv4 allocation CIDRs
	expectIPCacheUpdate(
		t, ipcacheMock, "delete", netip.MustParsePrefix("10.0.0.0/24"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.MustParsePrefix("192.168.10.0/28"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)

	// node IPv6 allocation CIDRs
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.MustParsePrefix("f00d::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)
	expectIPCacheUpdate(
		t, ipcacheMock, "delete", netip.MustParsePrefix("cafe::/96"),
		[]ipcache.IPMetadata{
			worldLabelForPrefix(netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)),
			ipcacheTypes.TunnelPeer{Addr: netip.MustParseAddr("10.0.0.2")},
			ipcacheTypes.EncryptKey(42),
		},
	)

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func TestNode(t *testing.T) {
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcacheMock, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("192.0.2.1")),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("2001:DB8::1")),
			},
		},
		IPv4HealthIP: iputil.AddrFrom(netip.MustParseAddr("192.0.2.2")),
		IPv6HealthIP: iputil.AddrFrom(netip.MustParseAddr("2001:DB8::2")),
		Source:       source.KVStore,
	}
	mngr.NodeUpdated(n1)

	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::1"), 128))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("192.0.2.2"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::2"), 128))

	n1V2 := n1.DeepCopy()
	n1V2.IPAddresses = []nodeTypes.Address{
		{
			Type: addressing.NodeCiliumInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("192.0.2.10")),
		},
		{
			// We will keep the IPv6 the same to make sure we will not delete it
			Type: addressing.NodeCiliumInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("2001:DB8::1")),
		},
	}
	n1V2.IPv4HealthIP = iputil.AddrFrom(netip.MustParseAddr("192.0.2.20"))
	n1V2.IPv6HealthIP = iputil.AddrFrom(netip.MustParseAddr("2001:DB8::20"))
	mngr.NodeUpdated(*n1V2)

	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("192.0.2.10"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::1"), 128))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("192.0.2.20"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::20"), 128))

	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("192.0.2.2"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "delete", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::2"), 128))

	select {
	case event := <-ipcacheMock.events:
		t.Errorf("Received unexpected event %+v", event)
	case <-time.After(1 * time.Second):
	}

	nodes := mngr.GetNodes()
	require.Len(t, nodes, 1)
	n, ok := nodes[n1.Identity()]
	require.True(t, ok)
	// Needs to be the same as n2
	require.Equal(t, *n1V2, n)
}

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ identity.IdentityMap) <-chan struct{} {
	out := make(chan struct{})
	close(out)
	return out
}

func TestNodeWithSameInternalIP(t *testing.T) {
	logger := hivetest.Logger(t)
	ctx, cancel := context.WithCancel(context.Background())
	allocator := testidentity.NewMockIdentityAllocator(nil)
	ipcache := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           ctx,
		Logger:            hivetest.Logger(t),
		IdentityAllocator: allocator,
		IdentityUpdater:   &mockUpdater{},
	})
	defer cancel()
	h, _ := cell.NewSimpleHealth()
	db := statedb.New()
	nodeTable, _ := node.NewNodeTable(db)
	writer := node.NewWriter(logger, db, nodeTable)
	mngr, err := New(logger, &option.DaemonConfig{
		LocalRouterIPv4: "169.254.4.6",
	}, cmtypes.DefaultClusterInfo, tunnel.Config{}, ipcache, NewNodeMetrics(), h, nil, db, nil, fakewireguard.Config{}, writer, testClusterSizeDependantInterval)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("10.128.0.40")),
			},
			{
				Type: addressing.NodeExternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("34.171.135.203")),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("169.254.4.6")),
			},
		},
		Source: source.Local,
	}
	mngr.NodeUpdated(n1)

	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("10.128.0.110")),
			},
			{
				Type: addressing.NodeExternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("34.170.71.139")),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   iputil.AddrFrom(netip.MustParseAddr("169.254.4.6")),
			},
		},
		Source: source.CustomResource,
	}
	mngr.NodeUpdated(n2)

}

func TestNodeTableMirroring(t *testing.T) {
	logger := hivetest.Logger(t)
	db := statedb.New()
	nodeTable, err := node.NewNodeTable(db)
	require.NoError(t, err)
	writer := node.NewWriter(logger, db, nodeTable)

	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(
		logger,
		&option.DaemonConfig{},
		cmtypes.ClusterInfo{Name: "c1"},
		tunnel.Config{},
		ipcacheMock,
		NewNodeMetrics(),
		h,
		nil,
		db,
		nil,
		fakewireguard.Config{},
		writer,
		testClusterSizeDependantInterval,
	)
	require.NoError(t, err)

	initialized, initWatch := nodeTable.Initialized(db.ReadTxn())
	require.False(t, initialized)
	require.ElementsMatch(t, []string{
		ClusterNodeTableInitializerName,
		MeshNodeTableInitializerName,
	}, nodeTable.PendingInitializers(db.ReadTxn()))

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		}},
		Source: source.KVStore,
	}
	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{{
			Type: addressing.NodeInternalIP,
			IP:   iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
		}},
		Source: source.KVStore,
	}

	requireNode := func(t *testing.T, n nodeTypes.Node) {
		stored, _, found := nodeTable.Get(db.ReadTxn(), node.NodeByName(n.Fullname()))
		require.True(t, found)
		require.Equal(t, n, stored.Node)
		require.Nil(t, stored.Local)
	}
	requireNoNode := func(t *testing.T, n nodeTypes.Node) {
		_, _, found := nodeTable.Get(db.ReadTxn(), node.NodeByName(n.Fullname()))
		require.False(t, found)
	}

	mngr.NodeUpdated(n1)
	requireNode(t, n1)

	txn := db.WriteTxn(nodeTable)
	stored, _, found := nodeTable.Get(txn, node.NodeByName(n1.Fullname()))
	require.True(t, found)
	stored = stored.DeepCopy()
	stored.Statuses = stored.Statuses.Set("test", reconciler.StatusDone())
	_, _, err = nodeTable.Insert(txn, stored)
	require.NoError(t, err)
	txn.Commit()

	n1.EncryptionKey = 42
	mngr.NodeUpdated(n1)
	requireNode(t, n1)
	stored, _, found = nodeTable.Get(db.ReadTxn(), node.NodeByName(n1.Fullname()))
	require.True(t, found)
	require.Equal(t, reconciler.StatusKindPending, stored.Statuses.Get("test").Kind)

	mngr.NodeUpdated(n2)
	requireNode(t, n1)
	requireNode(t, n2)

	select {
	case <-initWatch:
		t.Fatal("node table initialized before NodeSync")
	default:
	}

	initialized, _ = nodeTable.Initialized(db.ReadTxn())
	require.False(t, initialized)

	mngr.NodeSync()
	require.Equal(t, []string{
		MeshNodeTableInitializerName,
	}, nodeTable.PendingInitializers(db.ReadTxn()))

	select {
	case <-initWatch:
		t.Fatal("node table initialized before MeshNodeSync")
	default:
	}

	mngr.MeshNodeSync()

	select {
	case <-initWatch:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for node table initializer")
	}
	initialized, _ = nodeTable.Initialized(db.ReadTxn())
	require.True(t, initialized)

	mngr.NodeDeleted(n1)
	requireNoNode(t, n1)
	requireNode(t, n2)
}

func TestNodeTableInitializersCompleteInEitherOrder(t *testing.T) {
	for _, meshFirst := range []bool{false, true} {
		name := "cluster-first"
		if meshFirst {
			name = "mesh-first"
		}
		t.Run(name, func(t *testing.T) {
			db := statedb.New()
			nodeTable, err := node.NewNodeTable(db)
			require.NoError(t, err)
			writer := node.NewWriter(hivetest.Logger(t), db, nodeTable)

			health, _ := cell.NewSimpleHealth()
			mngr, err := New(
				hivetest.Logger(t),
				&option.DaemonConfig{},
				cmtypes.ClusterInfo{Name: "c1"},
				tunnel.Config{},
				newIPcacheMock(),
				NewNodeMetrics(),
				health,
				nil,
				db,
				nil,
				fakewireguard.Config{},
				writer,
				testClusterSizeDependantInterval,
			)
			require.NoError(t, err)

			if meshFirst {
				mngr.MeshNodeSync()
				require.Equal(t, []string{
					ClusterNodeTableInitializerName,
				}, nodeTable.PendingInitializers(db.ReadTxn()))
				mngr.NodeSync()
			} else {
				mngr.NodeSync()
				require.Equal(t, []string{
					MeshNodeTableInitializerName,
				}, nodeTable.PendingInitializers(db.ReadTxn()))
				mngr.MeshNodeSync()
			}

			initialized, _ := nodeTable.Initialized(db.ReadTxn())
			require.True(t, initialized)
		})
	}
}
