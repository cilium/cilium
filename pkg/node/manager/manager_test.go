// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package manager

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type managerTestSuite struct{}

var _ = check.Suite(&managerTestSuite{})

type configMock struct {
	Tunneling          bool
	RemoteNodeIdentity bool
	NodeEncryption     bool
	Encryption         bool
}

func (c *configMock) TunnelingEnabled() bool {
	return c.Tunneling
}

func (c *configMock) RemoteNodeIdentitiesEnabled() bool {
	return c.RemoteNodeIdentity
}

func (c *configMock) NodeEncryptionEnabled() bool {
	return c.NodeEncryption
}

func (c *configMock) EncryptionEnabled() bool {
	return c.Encryption
}

type nodeEvent struct {
	event ipcache.CacheModification
	cidr  string
}

type nodeEvents []nodeEvent

func (n nodeEvents) Len() int {
	return len(n)
}

func (n nodeEvents) Less(i, j int) bool {
	if n[i].event != n[j].event {
		return n[i].event < n[j].event
	}
	if n[i].cidr != n[j].cidr {
		return n[i].cidr < n[j].cidr
	}
	return false
}

func (n nodeEvents) Swap(i, j int) {
	n[i], n[j] = n[j], n[i]
}

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ cache.IdentityCache, _ *sync.WaitGroup) {}

type mockTriggerer struct{}

func (m *mockTriggerer) UpdatePolicyMaps(ctx context.Context, wg *sync.WaitGroup) *sync.WaitGroup {
	return wg
}

type ipcacheMock struct {
	*ipcache.IPCache
	events chan nodeEvent
}

func newIPcacheMock() *ipcacheMock {
	allocator := testidentity.NewMockIdentityAllocator(nil)
	i := &ipcacheMock{
		IPCache: ipcache.NewIPCache(&ipcache.Configuration{
			IdentityAllocator: allocator,
			PolicyHandler:     &mockUpdater{},
			DatapathHandler:   &mockTriggerer{},
		}),
		events: make(chan nodeEvent, 1024),
	}
	i.IPCache.AddListener(i)

	return i
}

func (i *ipcacheMock) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidr net.IPNet, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, k8sMeta *ipcache.K8sMetadata) {
	i.events <- nodeEvent{
		event: modType,
		cidr:  cidr.String(),
	}
}

func (i *ipcacheMock) OnIPIdentityCacheGC() {
	// no-op
}

func (i *ipcacheMock) expectEvents(c *check.C, expected []nodeEvent, timeout time.Duration) {
	obtained := make([]nodeEvent, 0, len(expected))
	timer := time.After(timeout)
	for len(obtained) < len(expected) {
		select {
		case ev, ok := <-i.events:
			if !ok {
				c.Errorf("Events channel closed unexpectedly.\nObtained: %v\nExpected: %v", obtained, expected)
				return
			}
			obtained = append(obtained, ev)
		case <-timer:
			c.Errorf("Timeout while waiting for IPCache events.\nObtained: %v\nExpected: %v", obtained, expected)
			return
		}
	}

	// IPCache event order is non-deterministic due to UpsertMetadata queuing
	// updates in a Go hash map (which as non-deterministic iteration order)
	sort.Stable(nodeEvents(obtained))
	sort.Stable(nodeEvents(expected))

	c.Assert(obtained, checker.DeepEquals, expected)
}

type signalNodeHandler struct {
	EnableNodeAddEvent                    bool
	NodeAddEvent                          chan nodeTypes.Node
	NodeUpdateEvent                       chan nodeTypes.Node
	EnableNodeUpdateEvent                 bool
	NodeDeleteEvent                       chan nodeTypes.Node
	EnableNodeDeleteEvent                 bool
	NodeValidateImplementationEvent       chan nodeTypes.Node
	EnableNodeValidateImplementationEvent bool
}

func newSignalNodeHandler() *signalNodeHandler {
	return &signalNodeHandler{
		NodeAddEvent:                    make(chan nodeTypes.Node, 10),
		NodeUpdateEvent:                 make(chan nodeTypes.Node, 10),
		NodeDeleteEvent:                 make(chan nodeTypes.Node, 10),
		NodeValidateImplementationEvent: make(chan nodeTypes.Node, 4096),
	}
}

func (n *signalNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	if n.EnableNodeAddEvent {
		n.NodeAddEvent <- newNode
	}
	return nil
}

func (n *signalNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	if n.EnableNodeUpdateEvent {
		n.NodeUpdateEvent <- newNode
	}
	return nil
}

func (n *signalNodeHandler) NodeDelete(node nodeTypes.Node) error {
	if n.EnableNodeDeleteEvent {
		n.NodeDeleteEvent <- node
	}
	return nil
}

func (n *signalNodeHandler) NodeValidateImplementation(node nodeTypes.Node) error {
	if n.EnableNodeValidateImplementationEvent {
		n.NodeValidateImplementationEvent <- node
	}
	return nil
}

func (n *signalNodeHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	return nil
}

func (n *signalNodeHandler) NodeNeighDiscoveryEnabled() bool {
	return false
}

func (n *signalNodeHandler) NodeNeighborRefresh(ctx context.Context, node nodeTypes.Node) {
	return
}

func (n *signalNodeHandler) NodeCleanNeighbors(migrateOnly bool) {
	return
}

func (s *managerTestSuite) SetUpSuite(c *check.C) {
}

func (s *managerTestSuite) TestNodeLifecycle(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", dp, &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)

	n1 := nodeTypes.Node{Name: "node1", Cluster: "c1"}
	mngr.NodeUpdated(n1)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	n2 := nodeTypes.Node{Name: "node2", Cluster: "c1"}
	mngr.NodeUpdated(n2)

	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n2)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	nodes := mngr.GetNodes()
	n, ok := nodes[n1.Identity()]
	c.Assert(ok, check.Equals, true)
	c.Assert(n, checker.DeepEquals, n1)

	mngr.NodeDeleted(n1)
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
	nodes = mngr.GetNodes()
	_, ok = nodes[n1.Identity()]
	c.Assert(ok, check.Equals, false)

	mngr.Close()
	select {
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n2)
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event for node2")
	}
}

func (s *managerTestSuite) TestMultipleSources(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", dp, &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1k8s := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Kubernetes}
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1k8s)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	// agent can overwrite kubernetes
	n1agent := nodeTypes.Node{Name: "node1", Cluster: "c1", Source: source.Local}
	mngr.NodeUpdated(n1agent)
	select {
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1agent)
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event for node1")
	}

	// kubernetes cannot overwrite local node
	mngr.NodeUpdated(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	// delete from kubernetes, should not remove local node
	mngr.NodeDeleted(n1k8s)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(100 * time.Millisecond):
	}

	mngr.NodeDeleted(n1agent)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1agent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
}

func (s *managerTestSuite) BenchmarkUpdateAndDeleteCycle(c *check.C) {
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", fake.NewNodeHandler(), &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeUpdated(n)
	}

	for i := 0; i < c.N; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeDeleted(n)
	}
	c.StopTimer()
}

func (s *managerTestSuite) TestClusterSizeDependantInterval(c *check.C) {
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", fake.NewNodeHandler(), &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	prevInterval := time.Nanosecond

	for i := 0; i < 1000; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local}
		mngr.NodeUpdated(n)
		newInterval := mngr.ClusterSizeDependantInterval(time.Minute)
		c.Assert(newInterval > prevInterval, check.Equals, true)
	}
}

func (s *managerTestSuite) TestBackgroundSync(c *check.C) {
	c.Skip("GH-6751 Test is disabled due to being unstable")

	// set the base background sync interval to a very low value so the
	// background sync runs aggressively
	baseBackgroundSyncIntervalBackup := baseBackgroundSyncInterval
	baseBackgroundSyncInterval = 10 * time.Millisecond
	defer func() { baseBackgroundSyncInterval = baseBackgroundSyncIntervalBackup }()

	signalNodeHandler := newSignalNodeHandler()
	signalNodeHandler.EnableNodeValidateImplementationEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", signalNodeHandler, &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	numNodes := 4096

	allNodeValidateCallsReceived := &sync.WaitGroup{}
	allNodeValidateCallsReceived.Add(1)

	go func() {
		nodeValidationsReceived := 0
		timer, timerDone := inctimer.New()
		defer timerDone()
		for {
			select {
			case <-signalNodeHandler.NodeValidateImplementationEvent:
				nodeValidationsReceived++
				if nodeValidationsReceived >= numNodes {
					allNodeValidateCallsReceived.Done()
					return
				}
			case <-timer.After(time.Second * 5):
				c.Errorf("Timeout while waiting for NodeValidateImplementation() to be called")
			}
		}
	}()

	for i := 0; i < numNodes; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Kubernetes}
		mngr.NodeUpdated(n)
	}

	allNodeValidateCallsReceived.Wait()
}

func (s *managerTestSuite) TestIpcache(c *check.C) {
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", newSignalNodeHandler(), &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Upsert, "1.1.1.1/32"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Delete, "1.1.1.1/32"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestIpcacheHealthIP(c *check.C) {
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", newSignalNodeHandler(), &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
		},
		IPv4HealthIP: net.ParseIP("10.0.0.4"),
		IPv6HealthIP: net.ParseIP("f00d::4"),
	}
	mngr.NodeUpdated(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Upsert, "1.1.1.1/32"},
		{ipcache.Upsert, "10.0.0.4/32"},
		{ipcache.Upsert, "f00d::4/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Delete, "1.1.1.1/32"},
		{ipcache.Delete, "10.0.0.4/32"},
		{ipcache.Delete, "f00d::4/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestRemoteNodeIdentities(c *check.C) {
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", newSignalNodeHandler(), &configMock{RemoteNodeIdentity: true}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Upsert, "1.1.1.1/32"},
		{ipcache.Upsert, "10.0.0.2/32"},
		{ipcache.Upsert, "f00d::1/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Delete, "1.1.1.1/32"},
		{ipcache.Delete, "10.0.0.2/32"},
		{ipcache.Delete, "f00d::1/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestNodeEncryption(c *check.C) {
	ipcacheMock := newIPcacheMock()
	mngr, err := NewManager("test", newSignalNodeHandler(), &configMock{NodeEncryption: true, Encryption: true}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.0.0.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Upsert, "1.1.1.1/32"},
		{ipcache.Upsert, "10.0.0.2/32"},
		{ipcache.Upsert, "f00d::1/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Delete, "1.1.1.1/32"},
		{ipcache.Delete, "10.0.0.2/32"},
		{ipcache.Delete, "f00d::1/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestNode(c *check.C) {
	ipcacheMock := newIPcacheMock()

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := NewManager("test", dp, &configMock{}, nil, nil)
	mngr = mngr.WithIPCache(ipcacheMock)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

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
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Upsert, "192.0.2.1/32"},
		{ipcache.Upsert, "2001:db8::1/128"},
		{ipcache.Upsert, "192.0.2.2/32"},
		{ipcache.Upsert, "2001:db8::2/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("Received unexpected event %s", event)
	case <-time.After(1 * time.Second):
	}

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
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Assert(nodeEvent, checker.DeepEquals, *n1V2)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeUpdate() event for node2")
	}

	ipcacheMock.expectEvents(c, []nodeEvent{
		{ipcache.Delete, "192.0.2.1/32"},
		{ipcache.Upsert, "192.0.2.10/32"},

		{ipcache.Delete, "192.0.2.2/32"},
		{ipcache.Upsert, "192.0.2.20/32"},

		{ipcache.Delete, "2001:db8::2/128"},
		{ipcache.Upsert, "2001:db8::20/128"},

		{ipcache.Upsert, "2001:db8::1/128"},
	}, 5*time.Second)

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("Received unexpected event %s", event)
	case <-time.After(1 * time.Second):
	}

	nodes := mngr.GetNodes()
	c.Assert(len(nodes), check.Equals, 1)
	n, ok := nodes[n1.Identity()]
	c.Assert(ok, check.Equals, true)
	// Needs to be the same as n2
	c.Assert(n, checker.DeepEquals, *n1V2)
}
