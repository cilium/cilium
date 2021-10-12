// Copyright 2018-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package manager

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/source"

	"gopkg.in/check.v1"
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
	event string
	ip    net.IP
}

type ipcacheMock struct {
	events chan nodeEvent
}

func newIPcacheMock() *ipcacheMock {
	return &ipcacheMock{
		events: make(chan nodeEvent, 1024),
	}
}

func (i *ipcacheMock) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error) {
	i.events <- nodeEvent{"upsert", net.ParseIP(ip)}
	return false, nil
}

func (i *ipcacheMock) Delete(IP string, source source.Source) bool {
	i.events <- nodeEvent{"delete", net.ParseIP(IP)}
	return false
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

func (n *signalNodeHandler) NodeCleanNeighbors() {
	return
}

func (s *managerTestSuite) TestNodeLifecycle(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := NewManager("test", dp, newIPcacheMock(), &configMock{})
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
	mngr, err := NewManager("test", dp, newIPcacheMock(), &configMock{})
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
	mngr, err := NewManager("test", fake.NewNodeHandler(), newIPcacheMock(), &configMock{})
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
	mngr, err := NewManager("test", fake.NewNodeHandler(), newIPcacheMock(), &configMock{})
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
	mngr, err := NewManager("test", signalNodeHandler, newIPcacheMock(), &configMock{})
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
	mngr, err := NewManager("test", newSignalNodeHandler(), ipcacheMock, &configMock{})
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("1.1.1.1")})
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
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("1.1.1.1")})
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
	mngr, err := NewManager("test", newSignalNodeHandler(), ipcacheMock, &configMock{})
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
		},
		IPv4HealthIP: net.ParseIP("4.4.4.4"),
		IPv6HealthIP: net.ParseIP("f00d::4"),
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("4.4.4.4")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 4.4.4.4")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("f00d::4")})
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
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("4.4.4.4")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 4.4.4.4")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("f00d::4")})
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
	mngr, err := NewManager("test", newSignalNodeHandler(), ipcacheMock, &configMock{RemoteNodeIdentity: true})
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("2.2.2.2")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 2.2.2.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("f00d::1")})
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
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("2.2.2.2")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 2.2.2.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("f00d::1")})
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
	mngr, err := NewManager("test", newSignalNodeHandler(), ipcacheMock, &configMock{NodeEncryption: true, Encryption: true})
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1 := nodeTypes.Node{
		Name:    "node1",
		Cluster: "c1",
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeCiliumInternalIP, IP: net.ParseIP("1.1.1.1")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2.2.2.2")},
			{Type: addressing.NodeExternalIP, IP: net.ParseIP("f00d::1")},
		},
	}
	mngr.NodeUpdated(n1)

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("2.2.2.2")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache upsert for IP 2.2.2.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "upsert", ip: net.ParseIP("f00d::1")})
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
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("1.1.1.1")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 1.1.1.1")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("2.2.2.2")})
	case <-time.After(5 * time.Second):
		c.Errorf("timeout while waiting for ipcache delete for IP 2.2.2.2")
	}

	select {
	case event := <-ipcacheMock.events:
		c.Assert(event, checker.DeepEquals, nodeEvent{event: "delete", ip: net.ParseIP("f00d::1")})
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
			c.Assert(event, checker.DeepEquals, nodeEvent{event: eventType, ip: net.ParseIP(ipStr)})
		case <-time.After(5 * time.Second):
			c.Errorf("timeout while waiting for ipcache upsert for IP %s", ipStr)
		}
	}

	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := NewManager("test", dp, ipcacheMock, &configMock{})
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
