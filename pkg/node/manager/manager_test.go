// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/health"
	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type nodeEvent struct {
	event    string
	prefix   netip.Prefix
	metadata ipcache.IPMetadata
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
func (i *ipcacheMock) OverrideIdentity(prefix cmtypes.PrefixCluster, identityLabels labels.Labels, src source.Source, resource ipcacheTypes.ResourceID) {
	i.UpsertMetadata(prefix, src, resource)
}

func (i *ipcacheMock) RemoveMetadata(prefix cmtypes.PrefixCluster, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
	i.Delete(prefix.String(), source.CustomResource, aux...)
}

func (i *ipcacheMock) RemoveIdentityOverride(prefix cmtypes.PrefixCluster, identityLabels labels.Labels, resource ipcacheTypes.ResourceID) {
	i.Delete(prefix.String(), source.CustomResource)
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

type ipsetMock struct {
	v4 map[string]struct{}
	v6 map[string]struct{}
}

func newIPSetMock() *ipsetMock {
	return &ipsetMock{
		v4: make(map[string]struct{}),
		v6: make(map[string]struct{}),
	}
}

type ipsetInitializerMock struct{}

func (i *ipsetInitializerMock) InitDone() {
}

func (i *ipsetMock) NewInitializer() ipset.Initializer {
	return &ipsetInitializerMock{}
}

func (i *ipsetMock) AddToIPSet(name string, family ipset.Family, addrs ...netip.Addr) {
	for _, addr := range addrs {
		if name == ipset.CiliumNodeIPSetV4 && family == ipset.INetFamily {
			i.v4[addr.String()] = struct{}{}
		} else if name == ipset.CiliumNodeIPSetV6 && family == ipset.INet6Family {
			i.v6[addr.String()] = struct{}{}
		}
	}
}

func (i *ipsetMock) RemoveFromIPSet(name string, addrs ...netip.Addr) {
	for _, addr := range addrs {
		if name == ipset.CiliumNodeIPSetV4 {
			delete(i.v4, addr.String())
		} else if name == ipset.CiliumNodeIPSetV6 {
			delete(i.v6, addr.String())
		}
	}
}

func ipsetContains(ipsetMgr *ipsetMock, setName string, addr string) (bool, error) {
	switch setName {
	case ipset.CiliumNodeIPSetV4:
		_, found := ipsetMgr.v4[addr]
		return found, nil
	case ipset.CiliumNodeIPSetV6:
		_, found := ipsetMgr.v6[addr]
		return found, nil
	default:
		return false, fmt.Errorf("unexpected ipset name %s", setName)
	}
}

type signalNodeHandler struct {
	EnableNodeAddEvent                    bool
	NodeAddEvent                          chan nodeTypes.Node
	NodeAddEventError                     error
	NodeUpdateEvent                       chan nodeTypes.Node
	NodeUpdateEventError                  error
	EnableNodeUpdateEvent                 bool
	NodeDeleteEvent                       chan nodeTypes.Node
	NodeDeleteEventError                  error
	EnableNodeDeleteEvent                 bool
	NodeValidateImplementationEvent       chan nodeTypes.Node
	NodeValidateImplementationEventError  error
	EnableNodeValidateImplementationEvent bool
	Stop                                  chan struct{}
}

func newSignalNodeHandler() *signalNodeHandler {
	return &signalNodeHandler{
		NodeAddEvent:                    make(chan nodeTypes.Node, 10),
		NodeUpdateEvent:                 make(chan nodeTypes.Node, 10),
		NodeDeleteEvent:                 make(chan nodeTypes.Node, 10),
		NodeValidateImplementationEvent: make(chan nodeTypes.Node, 4096),
		Stop:                            make(chan struct{}, 10),
	}
}

func (s *signalNodeHandler) Name() string {
	return "manager_test:signalNodeHandler"
}

func (n *signalNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	if n.EnableNodeAddEvent {
		n.NodeAddEvent <- newNode
	}
	return n.NodeAddEventError
}

func (n *signalNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	if n.EnableNodeUpdateEvent {
		n.NodeUpdateEvent <- newNode
	}
	return n.NodeUpdateEventError
}

func (n *signalNodeHandler) NodeDelete(node nodeTypes.Node) error {
	if n.EnableNodeDeleteEvent {
		n.NodeDeleteEvent <- node
	}
	return n.NodeDeleteEventError
}

func (n *signalNodeHandler) AllNodeValidateImplementation() {
}

func (n *signalNodeHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	if n.EnableNodeValidateImplementationEvent {
		select {
		case <-n.Stop:
		case n.NodeValidateImplementationEvent <- node:
		}
	}
	return n.NodeValidateImplementationEventError
}

func (n *signalNodeHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	return nil
}

func setup(tb testing.TB) {
	node.SetTestLocalNodeStore()

	tb.Cleanup(func() {
		node.UnsetTestLocalNodeStore()
	})
}

func TestNodeLifecycle(t *testing.T) {
	setup(t)
	logger := hivetest.Logger(t)

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	mngr.Subscribe(dp)
	require.NoError(t, err)

	n1 := nodeTypes.Node{Name: "node1", Cluster: "c1", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	},
		Source: source.Unspec,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n2 := nodeTypes.Node{Name: "node2", Cluster: "c1", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		},
	},
		Source: source.Unspec,
	}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n2, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	nodes := mngr.GetNodes()
	n, ok := nodes[n1.Identity()]
	require.True(t, ok)
	require.Equal(t, n1, n)

	mngr.NodeDeleted(n1)
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
	nodes = mngr.GetNodes()
	_, ok = nodes[n1.Identity()]
	require.False(t, ok)

	err = mngr.Stop(context.TODO())
	require.NoError(t, err)
}

func TestMultipleSources(t *testing.T) {
	setup(t)
	logger := hivetest.Logger(t)

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1k8s := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Kubernetes, IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	}}
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1k8s, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	// agent can overwrite kubernetes
	n1agent := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Local, IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	}}
	mngr.NodeUpdated(n1agent)
	select {
	case nodeEvent := <-dp.NodeUpdateEvent:
		require.Equal(t, n1agent, nodeEvent)
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event for node1")
	}

	// kubernetes cannot overwrite local node
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	// delete from kubernetes, should not remove local node
	mngr.NodeDeleted(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	mngr.NodeDeleted(n1agent)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		require.Equal(t, n1agent, nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
}

func BenchmarkUpdateAndDeleteCycle(b *testing.B) {
	ipcacheMock := newIPcacheMock()
	dp := fakeTypes.NewNodeHandler()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(b)
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(b, err)
	mngr.Subscribe(dp)
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

func TestClusterSizeDependantInterval(t *testing.T) {
	setup(t)
	logger := hivetest.Logger(t)

	ipcacheMock := newIPcacheMock()
	dp := fakeTypes.NewNodeHandler()
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	prevInterval := time.Nanosecond

	for i := range 1000 {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local, IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		}}
		mngr.NodeUpdated(n)
		newInterval := mngr.ClusterSizeDependantInterval(time.Minute)
		assert.Greater(t, newInterval, prevInterval)
	}
}

func TestBackgroundSync(t *testing.T) {
	signalNodeHandler := newSignalNodeHandler()
	signalNodeHandler.EnableNodeValidateImplementationEvent = true
	ipcacheMock := newIPcacheMock()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	mngr.Subscribe(signalNodeHandler)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	numNodes := 128

	allNodeValidateCallsReceived := &sync.WaitGroup{}
	allNodeValidateCallsReceived.Add(1)

	go func() {
		nodeValidationsReceived := 0
		for {
			select {
			case <-signalNodeHandler.NodeValidateImplementationEvent:
				nodeValidationsReceived++
				if nodeValidationsReceived >= numNodes {
					allNodeValidateCallsReceived.Done()
					return
				}
			case <-time.After(1 * time.Second):
				t.Errorf("Timeout while waiting for NodeValidateImplementation() to be called")
				allNodeValidateCallsReceived.Done()
				return
			}
		}
	}()

	for i := range numNodes {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Kubernetes, IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		}}
		mngr.NodeUpdated(n)
	}

	mngr.singleBackgroundLoop(context.Background(), time.Millisecond)

	allNodeValidateCallsReceived.Wait()
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
	dp := newSignalNodeHandler()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},

		IPv4AllocCIDR:           cidr.MustParseCIDR("10.0.0.0/24"),
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("192.168.10.0/28")},
		IPv6AllocCIDR:           cidr.MustParseCIDR("f00d::/96"),
		IPv6SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("cafe::/96")},
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
		return address.IP.Equal(net.ParseIP("f00d::1"))
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
	dp := newSignalNodeHandler()
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1").To4()},
		},
		IPv4HealthIP: net.ParseIP("10.0.0.4"),
		IPv6HealthIP: net.ParseIP("f00d::4"),
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
	setup(t)
	logger := hivetest.Logger(t)

	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{
		EncryptNode: true,
		EnableIPSec: true,
	}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
		IPv4AllocCIDR:           cidr.MustParseCIDR("10.0.0.0/24"),
		IPv4SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("192.168.10.0/28")},
		IPv6AllocCIDR:           cidr.MustParseCIDR("f00d::/96"),
		IPv6SecondaryAllocCIDRs: []*cidr.CIDR{cidr.MustParseCIDR("cafe::/96")},
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
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	logger := hivetest.Logger(t)
	mngr, err := New(logger, &option.DaemonConfig{}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("192.0.2.1"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("2001:DB8::1"),
			},
		},
		IPv4HealthIP: net.ParseIP("192.0.2.2"),
		IPv6HealthIP: net.ParseIP("2001:DB8::2"),
		Source:       source.KVStore,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::1"), 128))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("192.0.2.2"), 32))
	expectIPCacheUpdate(t, ipcacheMock, "upsert", netip.PrefixFrom(netip.MustParseAddr("2001:DB8::2"), 128))

	n1V2 := n1.DeepCopy()
	n1V2.IPAddresses = []nodeTypes.Address{
		{
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("192.0.2.10"),
		},
		{
			// We will keep the IPv6 the same to make sure we will not delete it
			Type: addressing.NodeCiliumInternalIP,
			IP:   net.ParseIP("2001:DB8::1"),
		},
	}
	n1V2.IPv4HealthIP = net.ParseIP("192.0.2.20")
	n1V2.IPv6HealthIP = net.ParseIP("2001:DB8::20")
	mngr.NodeUpdated(*n1V2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		require.Equal(t, *n1V2, nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

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

func TestNodeManagerEmitStatus(t *testing.T) {
	// Tests health reporting on node manager.
	assert := assert.New(t)

	var (
		statusTable statedb.Table[types.Status]
		db          *statedb.DB
		nh1         *signalNodeHandler
	)

	baseBackgroundSyncInterval = 1 * time.Millisecond
	fn := func(m *manager, sh hive.Shutdowner, st statedb.Table[types.Status], d *statedb.DB, lifecycle cell.Lifecycle) {
		m.nodes[nodeTypes.Identity{
			Name:    "node1",
			Cluster: "c1",
		}] = &nodeEntry{node: nodeTypes.Node{Name: "node1", Cluster: "c1"}}
		m.nodeHandlers = make(map[datapath.NodeHandler]struct{})
		nh1 = newSignalNodeHandler()
		nh1.EnableNodeValidateImplementationEvent = true
		// By default this is a buffered channel, by making it a non-buffered
		// channel we can sync up iterations of background sync.
		nh1.NodeValidateImplementationEvent = make(chan nodeTypes.Node)
		m.nodeHandlers[nh1] = struct{}{}

		statusTable = st
		db = d

		lifecycle.Append(m)
	}

	ipcacheMock := newIPcacheMock()
	config := &option.DaemonConfig{
		StateDir: t.TempDir(),
	}
	hive := hive.New(
		cell.Provide(func() testParams {
			return testParams{
				Config:        config,
				TunnelConf:    tunnel.Config{},
				IPCache:       ipcacheMock,
				IPSet:         newIPSetMock(),
				NodeMetrics:   NewNodeMetrics(),
				IPSetFilterFn: func(no *nodeTypes.Node) bool { return false },
			}
		}),
		cell.Provide(tables.NewDeviceTable),                   // Provide statedb.RWTable[*tables.Device]
		cell.Provide(statedb.RWTable[*tables.Device].ToTable), // Provide statedb.Table[*tables.Device] from RW table
		cell.Invoke(statedb.RegisterTable[*tables.Device]),
		cell.Module("node_manager", "Node Manager", cell.Provide(New)),
		cell.Invoke(fn),
	)
	l := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	hive.Populate(l)

	checkStatus := func() (types.Status, <-chan struct{}) {
		id := types.Identifier{
			Module:    cell.FullModuleID{"node_manager"},
			Component: []string{"job-backgroundSync"},
		}

		rx := db.ReadTxn()
		ss, _, watch, found := statusTable.GetWatch(rx, health.PrimaryIndex.Query(id.HealthID()))
		if !found {
			_, watch = statusTable.AllWatch(rx)
		}

		return ss, watch
	}

	err := hive.Start(l, context.Background())
	assert.NoError(err)
	defer hive.Stop(l, context.Background())

	// Initially the status does not exist. When the job starts to run, the
	// status will be "OK". Wait for the status to be "OK".
	var (
		status types.Status
		watch  <-chan struct{}
	)
	for {
		status, watch = checkStatus()
		if status.Level == "" {
			<-watch
			continue
		}

		assert.Equal(types.LevelOK, string(status.Level))
		break
	}

	// Unblock background sync by reading event. After this we expect the
	// status to switch to "Degraded", due to the test error set below
	nh1.NodeValidateImplementationEventError = fmt.Errorf("test error")
	<-nh1.NodeValidateImplementationEvent
	<-watch
	status, watch = checkStatus()
	assert.Equal(types.LevelDegraded, string(status.Level))

	// Stop returning an error and unblock background sync by reading event. After
	// this we expect the status to switch to "OK"
	nh1.NodeValidateImplementationEventError = nil
	<-nh1.NodeValidateImplementationEvent
	<-watch
	status, _ = checkStatus()
	assert.Equal(types.LevelOK, string(status.Level))

	for range cap(nh1.Stop) {
		nh1.Stop <- struct{}{}
	}
}

// TestCarrierDownReconciler tests that we can detect carrier down events for physical devices
// but ignore loopback devices.
func TestCarrierDownReconciler(t *testing.T) {
	// Declare values to use outside of hive later.
	var (
		m           *manager
		deviceTable statedb.RWTable[*tables.Device]
		db          *statedb.DB
	)

	// Use hive to create the manager and tables, mock the rest.
	h := hive.New(
		cell.Provide(tables.NewDeviceTable),                   // Provide statedb.RWTable[*tables.Device]
		cell.Provide(statedb.RWTable[*tables.Device].ToTable), // Provide statedb.Table[*tables.Device] from RW table
		cell.Invoke(statedb.RegisterTable[*tables.Device]),
		cell.Provide(func() testParams {
			return testParams{
				Config:        &option.DaemonConfig{},
				TunnelConf:    tunnel.Config{},
				IPCache:       newIPcacheMock(),
				IPSet:         newIPSetMock(),
				NodeMetrics:   NewNodeMetrics(),
				IPSetFilterFn: func(no *nodeTypes.Node) bool { return false },
			}
		}),
		cell.Module("node_manager", "Node Manager",
			cell.Provide(New),
		),
		cell.Invoke(func(manager *manager, dt statedb.RWTable[*tables.Device], database *statedb.DB) {
			m = manager
			deviceTable = dt
			db = database
		}),
	)

	// Just populate the hive, no need to start it.
	h.Populate(hivetest.Logger(t))

	// Add a node to the manager. When we decide to revalidate neighbors, we do so for all nodes
	// so we need at least one to be present otherwise we will never enqueue anything.
	m.nodes[nodeTypes.Identity{
		Name: "node1",
	}] = &nodeEntry{
		node: nodeTypes.Node{
			Name: "node1",
		},
	}

	// Stop the reconciler if things take to long.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create two devices, eth0 and lo. We will modify these devices to simulate carrier changes.
	tx := db.WriteTxn(deviceTable)
	_, _, err := deviceTable.Insert(tx, &tables.Device{
		Index:    1,
		Name:     "eth0",
		RawFlags: unix.IFF_UP | unix.IFF_RUNNING,
		Type:     "device",
	})
	if err != nil {
		tx.Abort()
		t.Fatal(err)
	}

	_, _, err = deviceTable.Insert(tx, &tables.Device{
		Index:    2,
		Name:     "lo",
		RawFlags: unix.IFF_UP | unix.IFF_RUNNING | unix.IFF_LOOPBACK,
		Type:     "device",
	})
	if err != nil {
		tx.Abort()
		t.Fatal(err)
	}

	tx.Commit()

	// Create a mock health reporter. We will the health reporting as a signal for when reconciliation
	// happened.
	mh := &mockHealth{ok: make(chan struct{}, 10)}
	// Wait for at least one OK signal, but consume more if there are any.
	wait := func() {
		<-mh.ok
	loop:
		for {
			select {
			case <-mh.ok:
			default:
				break loop
			}
		}
	}

	// Start the reconciler in the background.
	go m.carrierDownReconciler(ctx, mh)

	// Wait for the initial OK we get after initialization
	wait()

	// Modify eth0 so it is carrier down
	tx = db.WriteTxn(deviceTable)
	_, _, err = deviceTable.Insert(tx, &tables.Device{
		Index:    1,
		Name:     "eth0",
		RawFlags: unix.IFF_UP,
		Type:     "device",
	})
	if err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	tx.Commit()

	// Wait for reconciliation
	wait()

	if !m.nodeNeighborQueue.isEmpty() {
		t.Fatal("Expected nodeNeighborQueue to be empty")
	}

	// Modify eth0 so its carrier is up again.
	tx = db.WriteTxn(deviceTable)
	_, _, err = deviceTable.Insert(tx, &tables.Device{
		Index:    1,
		Name:     "eth0",
		RawFlags: unix.IFF_UP | unix.IFF_RUNNING,
		Type:     "device",
	})
	if err != nil {
		tx.Abort()
		t.Fatal(err)
	}
	tx.Commit()

	// Wait for reconciliation
	wait()

	if m.nodeNeighborQueue.isEmpty() {
		t.Fatal("Expected nodeNeighborQueue to not be empty")
	}
	// Drain the queue
	for _, more := m.nodeNeighborQueue.pop(); more; _, more = m.nodeNeighborQueue.pop() {
	}

	// Modify lo so its down
	tx = db.WriteTxn(deviceTable)
	_, _, err = deviceTable.Insert(tx, &tables.Device{
		Index:    2,
		Name:     "lo",
		RawFlags: unix.IFF_LOOPBACK,
		Type:     "device",
	})
	if err != nil {
		tx.Abort()
		t.Fatal(err)
	}

	tx.Commit()

	// Wait for reconciliation
	wait()

	if !m.nodeNeighborQueue.isEmpty() {
		t.Fatal("Expected nodeNeighborQueue to be empty")
	}

	// Modify lo so its carrier is up again.
	tx = db.WriteTxn(deviceTable)
	_, _, err = deviceTable.Insert(tx, &tables.Device{
		Index:    2,
		Name:     "lo",
		RawFlags: unix.IFF_UP | unix.IFF_RUNNING | unix.IFF_LOOPBACK,
		Type:     "device",
	})

	if err != nil {
		tx.Abort()
		t.Fatal(err)
	}

	tx.Commit()

	// Wait for reconciliation
	wait()

	// We expect the queue to still be empty since we should be ignoring changes
	// to loopback devices.
	if !m.nodeNeighborQueue.isEmpty() {
		t.Fatal("Expected nodeNeighborQueue to be empty")
	}

	cancel()
}

var _ cell.Health = (*mockHealth)(nil)

type mockHealth struct {
	ok chan struct{}
}

func (mh *mockHealth) OK(status string) {
	mh.ok <- struct{}{}
}

func (mh *mockHealth) Degraded(reason string, err error) {
}

func (mh *mockHealth) Stopped(reason string) {
}

func (mh *mockHealth) NewScope(name string) cell.Health {
	return mh
}

func (mh *mockHealth) Close() {}

type testParams struct {
	cell.Out
	Config        *option.DaemonConfig
	TunnelConf    tunnel.Config
	IPCache       IPCache
	IPSet         ipset.Manager
	NodeMetrics   *nodeMetrics
	IPSetFilterFn IPSetFilterFn
}

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ identity.IdentityMap, _ *sync.WaitGroup) (mutated bool) {
	return false
}

type mockTriggerer struct{}

func (m *mockTriggerer) UpdatePolicyMaps(ctx context.Context, wg *sync.WaitGroup) *sync.WaitGroup {
	return wg
}

func TestNodeWithSameInternalIP(t *testing.T) {
	logger := hivetest.Logger(t)
	ctx, cancel := context.WithCancel(context.Background())
	allocator := testidentity.NewMockIdentityAllocator(nil)
	ipcache := ipcache.NewIPCache(&ipcache.Configuration{
		Context:           ctx,
		Logger:            hivetest.Logger(t),
		IdentityAllocator: allocator,
		PolicyHandler:     &mockUpdater{},
		DatapathHandler:   &mockTriggerer{},
	})
	defer cancel()
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{
		LocalRouterIPv4: "169.254.4.6",
	}, tunnel.Config{}, ipcache, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.128.0.40"),
			},
			{
				Type: addressing.NodeExternalIP,
				IP:   net.ParseIP("34.171.135.203"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("169.254.4.6"),
			},
		},
		Source: source.Local,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.128.0.110"),
			},
			{
				Type: addressing.NodeExternalIP,
				IP:   net.ParseIP("34.170.71.139"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("169.254.4.6"),
			},
		},
		Source: source.CustomResource,
	}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n2, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event for node1")
	}
}

// TestNodeIpset tests that the ipset entries on the node are updated correctly
// when a node is updated or removed.
// It is inspired from TestNode() in manager_test.go.
func TestNodeIpset(t *testing.T) {
	logger := hivetest.Logger(t)
	ipsetExpect := func(ipsetMgr *ipsetMock, ip string, expected bool) {
		setName := ipset.CiliumNodeIPSetV6
		if v4 := net.ParseIP(ip).To4(); v4 != nil {
			setName = ipset.CiliumNodeIPSetV4
		}

		found, err := ipsetContains(ipsetMgr, setName, strings.ToLower(ip))
		require.NoError(t, err)

		if found && !expected {
			t.Errorf("ipset %s contains IP %s but it should not", setName, ip)
		}
		if !found && expected {
			t.Errorf("ipset %s does not contain expected IP %s", setName, ip)
		}
	}

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	filter := func(no *nodeTypes.Node) bool { return no.Name != "node1" }
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{
		RoutingMode:          option.RoutingModeNative,
		EnableIPv4Masquerade: true,
	}, tunnel.Config{}, newIPcacheMock(), newIPSetMock(), filter, NewNodeMetrics(), h, nil, nil, nil)
	mngr.Subscribe(dp)
	require.NoError(t, err)
	defer mngr.Stop(context.TODO())

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("192.0.2.1"),
			},
			{
				Type: addressing.NodeCiliumInternalIP,
				IP:   net.ParseIP("2001:DB8::1"),
			},
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("2001:ABCD::1"),
			},
		},
		IPv4HealthIP: net.ParseIP("192.0.2.2"),
		IPv6HealthIP: net.ParseIP("2001:DB8::2"),
		Source:       source.KVStore,
	}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event")
	}

	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "192.0.2.1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:DB8::1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "10.0.0.1", true)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:ABCD::1", true)

	n2 := nodeTypes.Node{
		Name:    "node2",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.1.0.1"),
			},
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("2001:ABCE::1"),
			},
		},
		Source: source.CustomResource,
	}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		require.Equal(t, n2, nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeAdd() event")
	}

	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "10.0.0.1", true)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:ABCD::1", true)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "10.1.0.1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:ABCE::1", false)

	n1.IPv4HealthIP = net.ParseIP("192.0.2.20")
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		t.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeUpdate() event")
	}

	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "192.0.2.1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:DB8::1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "10.0.0.1", true)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:ABCD::1", true)

	mngr.NodeDeleted(n1)
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		require.Equal(t, n1, nodeEvent)
	case nodeEvent := <-dp.NodeAddEvent:
		t.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		t.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		t.Errorf("timeout while waiting for NodeDelete() event")
	}

	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "192.0.2.1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:DB8::1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "10.0.0.1", false)
	ipsetExpect(mngr.ipsetMgr.(*ipsetMock), "2001:ABCD::1", false)
}

// Tests that the node manager calls delete on nodes to be pruned.
func TestNodesStartupPruning(t *testing.T) {
	logger := hivetest.Logger(t)
	n1 := nodeTypes.Node{Name: "node1", Cluster: "c1", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	}}

	n2 := nodeTypes.Node{Name: "node2", Cluster: "c1", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		},
	}}

	n3 := nodeTypes.Node{Name: "node3", Cluster: "c2", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.3"),
		},
	}}

	// Create a nodes.json file from the above two nodes, simulating a previous instance of the agent.
	tmp := t.TempDir()
	path := filepath.Join(tmp, nodesFilename)
	nf, err := os.Create(path)
	require.NoError(t, err)
	t.Cleanup(func() {
		nf.Close()
		os.Remove(path)
	})
	e := json.NewEncoder(nf)
	require.NoError(t, e.Encode([]nodeTypes.Node{n3, n2, n1}))
	require.NoError(t, nf.Sync())
	require.NoError(t, nf.Close())

	checkNodeFileMatches := func(path string, node nodeTypes.Node) {
		// Wait until the file exists. The node deletion triggers the write, hence
		// this shouldn't take long.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.FileExists(c, path)
		}, time.Second, 10*time.Millisecond)
		nwf, err := os.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() {
			nwf.Close()
		})
		var nl []nodeTypes.Node
		assert.NoError(t, json.NewDecoder(nwf).Decode(&nl))
		assert.Len(t, nl, 1)
		assert.Equal(t, node, nl[0])
		require.NoError(t, os.Remove(path))
	}

	// Create a node manager and add only node1.
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	dp.EnableNodeDeleteEvent = true
	h, _ := cell.NewSimpleHealth()
	mngr, err := New(logger, &option.DaemonConfig{
		StateDir:    tmp,
		ClusterName: "c1",
	}, tunnel.Config{}, ipcacheMock, newIPSetMock(), nil, NewNodeMetrics(), h, nil, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		mngr.Stop(context.TODO())
	})
	mngr.Subscribe(dp)
	mngr.NodeUpdated(n1)

	// Load the nodes from disk and initiate pruning. This should prune node 2
	// (since it's present in the file but not in our current view).
	mngr.restoreNodeCheckpoint()
	require.NoError(t, mngr.initNodeCheckpointer(time.Microsecond))
	// We remove our test file here to be able to tell once the nodemanager has
	// written one itself.
	require.NoError(t, os.Remove(path))
	// Declare cluster nodes synced (but not clustermesh nodes)
	mngr.NodeSync()

	select {
	case dn := <-dp.NodeDeleteEvent:
		n2r := n2
		n2r.Source = source.Restored
		assert.Equal(t, n2r, dn, "should have deleted node 2 and (with source=Restored)")
	case <-time.After(time.Second * 5):
		t.Fatal("should have received a node deletion event for node 2")
	}

	checkNodeFileMatches(path, n1)

	// Allow pruning the clustermesh node.
	mngr.MeshNodeSync()

	select {
	case dn := <-dp.NodeDeleteEvent:
		n3r := n3
		n3r.Source = source.Restored
		assert.Equal(t, n3r, dn, "should have deleted node 3 and (with source=Restored)")
	case <-time.After(time.Second * 5):
		t.Fatal("should have received a node deletion event for node 3")
	}

	checkNodeFileMatches(path, n1)
}
