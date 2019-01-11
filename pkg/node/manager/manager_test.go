// Copyright 2018-2019 Authors of Cilium
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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/node"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type managerTestSuite struct{}

var _ = check.Suite(&managerTestSuite{})

type signalNodeHandler struct {
	EnableNodeAddEvent                    bool
	NodeAddEvent                          chan node.Node
	NodeUpdateEvent                       chan node.Node
	EnableNodeUpdateEvent                 bool
	NodeDeleteEvent                       chan node.Node
	EnableNodeDeleteEvent                 bool
	NodeValidateImplementationEvent       chan node.Node
	EnableNodeValidateImplementationEvent bool
}

func newSignalNodeHandler() *signalNodeHandler {
	return &signalNodeHandler{
		NodeAddEvent:                    make(chan node.Node, 10),
		NodeUpdateEvent:                 make(chan node.Node, 10),
		NodeDeleteEvent:                 make(chan node.Node, 10),
		NodeValidateImplementationEvent: make(chan node.Node, 4096),
	}
}

func (n *signalNodeHandler) NodeAdd(newNode node.Node) error {
	if n.EnableNodeAddEvent {
		n.NodeAddEvent <- newNode
	}
	return nil
}

func (n *signalNodeHandler) NodeUpdate(oldNode, newNode node.Node) error {
	if n.EnableNodeUpdateEvent {
		n.NodeUpdateEvent <- newNode
	}
	return nil
}

func (n *signalNodeHandler) NodeDelete(node node.Node) error {
	if n.EnableNodeDeleteEvent {
		n.NodeDeleteEvent <- node
	}
	return nil
}

func (n *signalNodeHandler) NodeValidateImplementation(node node.Node) error {
	if n.EnableNodeValidateImplementationEvent {
		n.NodeValidateImplementationEvent <- node
	}
	return nil
}

func (n *signalNodeHandler) NodeConfigurationChanged(config datapath.LocalNodeConfiguration) error {
	return nil
}

func (s *managerTestSuite) TestNodeLifecycle(c *check.C) {
	dp := newSignalNodeHandler()
	dp.EnableNodeAddEvent = true
	dp.EnableNodeUpdateEvent = true
	dp.EnableNodeDeleteEvent = true
	mngr, err := NewManager("test", dp)
	c.Assert(err, check.IsNil)

	n1 := node.Node{Name: "node1", Cluster: "c1"}
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

	n2 := node.Node{Name: "node2", Cluster: "c1"}
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
	mngr, err := NewManager("test", dp)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	n1k8s := node.Node{Name: "node1", Cluster: "c1", Source: node.FromKubernetes}
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
	n1agent := node.Node{Name: "node1", Cluster: "c1", Source: node.FromAgentLocal}
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

	// local node can overwrite agent
	n1local := node.Node{Name: "node1", Cluster: "c1", Source: node.FromLocalNode}
	mngr.NodeUpdated(n1local)
	select {
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1local)
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

	mngr.NodeDeleted(n1local)
	select {
	case nodeEvent := <-dp.NodeAddEvent:
		c.Errorf("Unexpected NodeAdd() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeUpdateEvent:
		c.Errorf("Unexpected NodeUpdate() event %#v", nodeEvent)
	case nodeEvent := <-dp.NodeDeleteEvent:
		c.Assert(nodeEvent, checker.DeepEquals, n1local)
	case <-time.After(3 * time.Second):
		c.Errorf("timeout while waiting for NodeDelete() event for node1")
	}
}

func (s *managerTestSuite) TestOverwriteAllowed(c *check.C) {
	type testExpectation struct {
		old    node.Source
		new    node.Source
		result bool
	}

	expectations := []testExpectation{
		// FromLocalNode -> [*]
		{old: node.FromLocalNode, new: node.FromLocalNode, result: true},
		{old: node.FromLocalNode, new: node.FromAgentLocal, result: false},
		{old: node.FromLocalNode, new: node.FromKVStore, result: false},
		{old: node.FromLocalNode, new: node.FromKubernetes, result: false},
		{old: node.FromLocalNode, new: "unknown", result: false},

		// FromAgentLocal -> [*]
		{old: node.FromAgentLocal, new: node.FromLocalNode, result: true},
		{old: node.FromAgentLocal, new: node.FromAgentLocal, result: true},
		{old: node.FromAgentLocal, new: node.FromKVStore, result: false},
		{old: node.FromAgentLocal, new: node.FromKubernetes, result: false},
		{old: node.FromAgentLocal, new: "unknown", result: false},

		// FromKVStore -> [*]
		{old: node.FromAgentLocal, new: node.FromLocalNode, result: true},
		{old: node.FromKVStore, new: node.FromAgentLocal, result: true},
		{old: node.FromKVStore, new: node.FromKVStore, result: true},
		{old: node.FromKVStore, new: node.FromKubernetes, result: false},
		{old: node.FromKVStore, new: "unknown", result: false},

		// FromKubernetes -> [*]
		{old: node.FromAgentLocal, new: node.FromLocalNode, result: true},
		{old: node.FromKubernetes, new: node.FromAgentLocal, result: true},
		{old: node.FromKubernetes, new: node.FromKVStore, result: true},
		{old: node.FromKubernetes, new: node.FromKubernetes, result: true},
		{old: node.FromKubernetes, new: "unknown", result: false},

		// Unknown -> [*]
		{old: "unknown", new: node.FromLocalNode, result: true},
		{old: "unknown", new: node.FromAgentLocal, result: true},
		{old: "unknown", new: node.FromKVStore, result: true},
		{old: "unknown", new: node.FromKubernetes, result: true},
		{old: "unknown", new: "unknown", result: false},
	}

	for _, e := range expectations {
		if overwriteAllowed(e.old, e.new) != e.result {
			c.Errorf("Unexpected result of overwriteAllowed(%s, %s) == %t", e.old, e.new, e.result)
		}
	}
}

func (s *managerTestSuite) BenchmarkUpdateAndDeleteCycle(c *check.C) {
	mngr, err := NewManager("test", fake.NewNodeHandler())
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		n := node.Node{Name: fmt.Sprintf("%d", i), Source: node.FromAgentLocal}
		mngr.NodeUpdated(n)
	}

	for i := 0; i < c.N; i++ {
		n := node.Node{Name: fmt.Sprintf("%d", i), Source: node.FromAgentLocal}
		mngr.NodeDeleted(n)
	}
	c.StopTimer()
}

func (s *managerTestSuite) TestBackgroundSyncInterval(c *check.C) {
	mngr, err := NewManager("test", fake.NewNodeHandler())
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	prevInterval := time.Nanosecond

	for i := 0; i < 1000; i++ {
		n := node.Node{Name: fmt.Sprintf("%d", i), Source: node.FromAgentLocal}
		mngr.NodeUpdated(n)
		newInterval := mngr.backgroundSyncInterval()
		c.Assert(newInterval > prevInterval, check.Equals, true)
	}
}

func (s *managerTestSuite) TestBackgroundSync(c *check.C) {
	// set the base background sync interval to a very low value so the
	// background sync runs aggressively
	baseBackgroundSyncIntervalBackup := baseBackgroundSyncInterval
	baseBackgroundSyncInterval = float64((10 * time.Millisecond).Nanoseconds())
	defer func() { baseBackgroundSyncInterval = baseBackgroundSyncIntervalBackup }()

	signalNodeHandler := newSignalNodeHandler()
	signalNodeHandler.EnableNodeValidateImplementationEvent = true
	mngr, err := NewManager("test", signalNodeHandler)
	c.Assert(err, check.IsNil)
	defer mngr.Close()

	numNodes := 4096

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
			case <-time.After(time.Second * 5):
				c.Errorf("Timeout while waiting for NodeValidateImplementation() to be called")
			}
		}
	}()

	for i := 0; i < numNodes; i++ {
		n := node.Node{Name: fmt.Sprintf("%d", i), Source: node.FromKubernetes}
		mngr.NodeUpdated(n)
	}

	allNodeValidateCallsReceived.Wait()
}
