// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath/fake"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"
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
	event  string
	prefix netip.Prefix
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

func (i *ipcacheMock) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	addr, err := AddrOrPrefixToIP(ip)
	if err != nil {
		i.events <- nodeEvent{fmt.Sprintf("upsert failed: %s", err), addr}
		return false, err
	}
	i.events <- nodeEvent{"upsert", addr}
	return false, nil
}

func (i *ipcacheMock) Delete(ip string, source source.Source) bool {
	addr, err := AddrOrPrefixToIP(ip)
	if err != nil {
		i.events <- nodeEvent{fmt.Sprintf("delete failed: %s", err), addr}
		return false
	}
	i.events <- nodeEvent{"delete", addr}
	return false
}

func (i *ipcacheMock) GetMetadataByPrefix(prefix netip.Prefix) ipcache.PrefixInfo {
	return ipcache.PrefixInfo{}
}
func (i *ipcacheMock) UpsertMetadata(prefix netip.Prefix, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
	i.Upsert(prefix.String(), nil, 0, nil, ipcache.Identity{})
}
func (i *ipcacheMock) OverrideIdentity(prefix netip.Prefix, identityLabels labels.Labels, src source.Source, resource ipcacheTypes.ResourceID) {
	i.UpsertMetadata(prefix, src, resource)
}

func (i *ipcacheMock) RemoveMetadata(prefix netip.Prefix, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata) {
	i.Delete(prefix.String(), source.CustomResource)
}

func (i *ipcacheMock) RemoveIdentityOverride(prefix netip.Prefix, identityLabels labels.Labels, resource ipcacheTypes.ResourceID) {
	i.Delete(prefix.String(), source.CustomResource)
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

func (s *managerTestSuite) SetUpSuite(c *check.C) {
}

func (s *managerTestSuite) TestNodeLifecycle(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	mngr.Subscribe(dp)
	c.Assert(err, check.IsNil)

	n1 := nodeTypes.Node{Name: "node1", Cluster: "c1", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.1"),
		},
	}}
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

	n2 := nodeTypes.Node{Name: "node2", Cluster: "c1", IPAddresses: []nodeTypes.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   net.ParseIP("10.0.0.2"),
		},
	}}
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

	err = mngr.Stop(context.TODO())
	c.Assert(err, check.IsNil)
}

func (s *managerTestSuite) TestMultipleSources(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	ipcacheMock := newIPcacheMock()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
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
		c.Assert(nodeEvent, checker.DeepEquals, n1k8s)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
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
	dp := fake.NewNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

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
	dp := fake.NewNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
	mngr.Subscribe(dp)
	defer mngr.Stop(context.TODO())

	prevInterval := time.Nanosecond

	for i := 0; i < 1000; i++ {
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Local, IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		}}
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
	mngr, err := New("test", &configMock{}, ipcacheMock)
	mngr.Subscribe(signalNodeHandler)
	c.Assert(err, check.IsNil)
	defer mngr.Stop(context.TODO())

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
		n := nodeTypes.Node{Name: fmt.Sprintf("%d", i), Source: source.Kubernetes, IPAddresses: []nodeTypes.Address{
			{
				Type: addressing.NodeInternalIP,
				IP:   net.ParseIP("10.0.0.1"),
			},
		}}
		mngr.NodeUpdated(n)
	}

	allNodeValidateCallsReceived.Wait()
}

func (s *managerTestSuite) TestIpcache(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
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
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestIpcacheHealthIP(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
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

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.4"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 10.0.0.4")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("f00d::4"), 128)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP f00d::4")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.4"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 10.0.0.4")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("f00d::4"), 128)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP f00d::4")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestRemoteNodeIdentities(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{RemoteNodeIdentity: true}, ipcacheMock)
	c.Assert(err, check.IsNil)
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
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 10.0.0.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP f00d::1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 10.0.0.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP f00d::1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestNodeEncryption(c *check.C) {
	ipcacheMock := newIPcacheMock()
	dp := newSignalNodeHandler()
	mngr, err := New("test", &configMock{NodeEncryption: true, Encryption: true}, ipcacheMock)
	c.Assert(err, check.IsNil)
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
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 10.0.0.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", prefix: netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP f00d::1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}

	mngr.NodeDeleted(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("1.1.1.1"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.2"), 32)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 10.0.0.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", prefix: netip.PrefixFrom(netip.MustParseAddr("f00d::1"), 128)})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP f00d::1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Errorf("unexected ipcache interaction %+v", event)
	default:
	}
}

func (s *managerTestSuite) TestNode(c *check.C) {
	ipcacheMock := newIPcacheMock()
	ipcacheExpect := func(eventType, ipStr string) {
		select {
		case event := <-ipcacheMock.events:
			b := 32
			if strings.Contains(ipStr, ":") {
				b = 128
			}
			if !c.Check(event, checker.DeepEquals, nodeEvent{event: eventType, prefix: netip.PrefixFrom(netip.MustParseAddr(ipStr), b)}) {
				// Panic just to get a stack trace so you can find the source of the problem
				panic("assertion failed")
			}
		case <-time.After(5 * time.Second):
			c.Errorf("timeout while waiting for ipcache upsert for IP %s", ipStr)
		}
	}

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := New("test", &configMock{}, ipcacheMock)
	c.Assert(err, check.IsNil)
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
		c.Assert(nodeEvent, checker.DeepEquals, n1)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Errorf("Unexpected NodeDelete() event %#v", nodeEvent)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeAdd() event for node1")
	}

	ipcacheExpect("upsert", "192.0.2.1")
	ipcacheExpect("upsert", "2001:DB8::1")
	ipcacheExpect("upsert", "192.0.2.2")
	ipcacheExpect("upsert", "2001:DB8::2")

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

	ipcacheExpect("upsert", "192.0.2.10")
	ipcacheExpect("upsert", "2001:DB8::1")
	ipcacheExpect("upsert", "192.0.2.20")
	ipcacheExpect("upsert", "2001:DB8::20")

	ipcacheExpect("delete", "192.0.2.1")
	ipcacheExpect("delete", "192.0.2.2")
	ipcacheExpect("delete", "2001:DB8::2")

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
