// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"sync"
	"time"

	check "github.com/cilium/checkmate"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	k8sapi     = &k8sMock{}
	metricsapi = metricsmock.NewMockMetrics()
)

const testPoolID = ipamTypes.PoolID("global")

type allocationImplementationMock struct {
	// mutex protects all fields of this structure
	mutex        lock.RWMutex
	poolSize     int
	allocatedIPs int
	ipGenerator  int
}

func newAllocationImplementationMock() *allocationImplementationMock {
	return &allocationImplementationMock{poolSize: 2048}
}

func (a *allocationImplementationMock) CreateNode(obj *v2.CiliumNode, node *Node) NodeOperations {
	return &nodeOperationsMock{allocator: a}
}

func (a *allocationImplementationMock) GetPoolQuota() ipamTypes.PoolQuotaMap {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return ipamTypes.PoolQuotaMap{
		testPoolID: ipamTypes.PoolQuota{AvailableIPs: a.poolSize - a.allocatedIPs},
	}
}

func (a *allocationImplementationMock) Resync(ctx context.Context) time.Time {
	return time.Now()
}

func (a *allocationImplementationMock) HasInstance(instanceID string) bool {
	return true
}

func (a *allocationImplementationMock) DeleteInstance(instanceID string) {
}

type nodeOperationsMock struct {
	allocator *allocationImplementationMock

	// mutex protects allocatedIPs
	mutex        lock.RWMutex
	allocatedIPs []string
}

func (n *nodeOperationsMock) GetUsedIPWithPrefixes() int {
	return len(n.allocatedIPs)
}

func (n *nodeOperationsMock) UpdatedNode(obj *v2.CiliumNode) {}

func (n *nodeOperationsMock) PopulateStatusFields(resource *v2.CiliumNode) {}

func (n *nodeOperationsMock) CreateInterface(ctx context.Context, allocation *AllocationAction, scopedLog *logrus.Entry) (int, string, error) {
	return 0, "operation not supported", fmt.Errorf("operation not supported")
}

func (n *nodeOperationsMock) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (
	ipamTypes.AllocationMap,
	ipamStats.InterfaceStats,
	error) {
	var stats ipamStats.InterfaceStats
	available := ipamTypes.AllocationMap{}
	n.mutex.RLock()
	for _, ip := range n.allocatedIPs {
		available[ip] = ipamTypes.AllocationIP{}
	}
	n.mutex.RUnlock()
	return available, stats, nil
}

func (n *nodeOperationsMock) PrepareIPAllocation(scopedLog *logrus.Entry) (*AllocationAction, error) {
	n.allocator.mutex.RLock()
	defer n.allocator.mutex.RUnlock()
	return &AllocationAction{
		PoolID:                 testPoolID,
		AvailableForAllocation: n.allocator.poolSize - n.allocator.allocatedIPs,
	}, nil
}

func (n *nodeOperationsMock) AllocateIPs(ctx context.Context, allocation *AllocationAction) error {
	n.mutex.Lock()
	n.allocator.mutex.Lock()
	n.allocator.allocatedIPs += allocation.AvailableForAllocation
	for i := 0; i < allocation.AvailableForAllocation; i++ {
		n.allocator.ipGenerator++
		n.allocatedIPs = append(n.allocatedIPs, fmt.Sprintf("%d", n.allocator.ipGenerator))
	}
	n.allocator.mutex.Unlock()
	n.mutex.Unlock()
	return nil
}

func (n *nodeOperationsMock) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry) *ReleaseAction {
	n.mutex.RLock()
	excessIPs = math.IntMin(excessIPs, len(n.allocatedIPs))
	r := &ReleaseAction{PoolID: testPoolID}
	for i := 1; i <= excessIPs; i++ {
		// Release from the end of slice to avoid releasing used IPs
		releaseIndex := len(n.allocatedIPs) - (excessIPs + i - 1)
		r.IPsToRelease = append(r.IPsToRelease, n.allocatedIPs[releaseIndex])
	}
	n.mutex.RUnlock()
	return r
}

func (n *nodeOperationsMock) releaseIP(ip string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.allocator.mutex.Lock()
	defer n.allocator.mutex.Unlock()
	for i, allocatedIP := range n.allocatedIPs {
		if allocatedIP == ip {
			n.allocatedIPs = append(n.allocatedIPs[:i], n.allocatedIPs[i+1:]...)
			n.allocator.allocatedIPs--
			return nil
		}
	}
	return fmt.Errorf("IP %s not found", ip)
}

func (n *nodeOperationsMock) ReleaseIPs(ctx context.Context, release *ReleaseAction) error {
	for _, ipToDelete := range release.IPsToRelease {
		if err := n.releaseIP(ipToDelete); err != nil {
			return fmt.Errorf("unable to release IP %s: %s", ipToDelete, err)
		}
	}
	return nil
}

func (n *nodeOperationsMock) GetMaximumAllocatableIPv4() int {
	return 0
}

func (n *nodeOperationsMock) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

func (n *nodeOperationsMock) IsPrefixDelegated() bool {
	return false
}

func (e *IPAMSuite) TestGetNodeNames(c *check.C) {
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	node1 := newCiliumNode("node1", 0, 0, 0)
	mngr.Update(node1)

	names := mngr.GetNames()
	c.Assert(len(names), check.Equals, 1)
	c.Assert(names[0], check.Equals, "node1")

	mngr.Update(newCiliumNode("node2", 0, 0, 0))

	names = mngr.GetNames()
	c.Assert(len(names), check.Equals, 2)

	mngr.Delete(node1)

	names = mngr.GetNames()
	c.Assert(len(names), check.Equals, 1)
	c.Assert(names[0], check.Equals, "node2")
}

func (e *IPAMSuite) TestNodeManagerGet(c *check.C) {
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// instances.Resync(context.TODO())

	node1 := newCiliumNode("node1", 0, 0, 0)
	mngr.Update(node1)

	c.Assert(mngr.Get("node1"), check.Not(check.IsNil))
	c.Assert(mngr.Get("node2"), check.IsNil)

	mngr.Delete(node1)
	c.Assert(mngr.Get("node1"), check.IsNil)
	c.Assert(mngr.Get("node2"), check.IsNil)
}

type k8sMock struct{}

func (k *k8sMock) Update(origNode, orig *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	return nil, nil
}

func (k *k8sMock) Get(node string) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func (k *k8sMock) Create(*v2.CiliumNode) (*v2.CiliumNode, error) {
	return &v2.CiliumNode{}, nil
}

func newCiliumNode(node string, preAllocate, minAllocate, used int) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pool:        ipamTypes.AllocationMap{},
				PreAllocate: preAllocate,
				MinAllocate: minAllocate,
			},
		},
		Status: v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				Used:       ipamTypes.AllocationMap{},
				ReleaseIPs: map[string]ipamTypes.IPReleaseStatus{},
			},
		},
	}

	updateCiliumNode(cn, used)

	return cn
}

func updateCiliumNode(cn *v2.CiliumNode, used int) *v2.CiliumNode {
	cn.Spec.IPAM.Pool = ipamTypes.AllocationMap{}
	for i := 1; i <= used; i++ {
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = ipamTypes.AllocationIP{Resource: "foo"}
	}

	cn.Status.IPAM.Used = ipamTypes.AllocationMap{}
	for ip, ipAllocation := range cn.Spec.IPAM.Pool {
		if used > 0 {
			delete(cn.Spec.IPAM.Pool, ip)
			cn.Status.IPAM.Used[ip] = ipAllocation
			used--
		}
	}

	return cn
}

func reachedAddressesNeeded(mngr *NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededAddresses() == needed
	}
	return
}

// TestNodeManagerDefaultAllocation tests allocation with default parameters
//
// - MinAllocate 0
// - PreAllocate 8
func (e *IPAMSuite) TestNodeManagerDefaultAllocation(c *check.C) {
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", 8, 0, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 8)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// Use 7 out of 8 IPs
	mngr.Update(updateCiliumNode(cn, 7))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node1")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 15)
	c.Assert(node.Stats().UsedIPs, check.Equals, 7)
}

// TestNodeManagerMinAllocate20 tests MinAllocate without PreAllocate
//
// - MinAllocate 10
// - PreAllocate -1
func (e *IPAMSuite) TestNodeManagerMinAllocate20(c *check.C) {
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node2", -1, 10, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 10)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// 10 available, 8 used
	mngr.Update(updateCiliumNode(cn, 8))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 10)
	c.Assert(node.Stats().UsedIPs, check.Equals, 8)

	// Change MinAllocate to 20
	mngr.Update(newCiliumNode("node2", 0, 20, 8))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().UsedIPs, check.Equals, 8)
	c.Assert(node.Stats().AvailableIPs, check.Equals, 20)
}

// TestNodeManagerMinAllocateAndPreallocate tests MinAllocate in combination with PreAllocate
//
// - MinAllocate 10
// - PreAllocate 1
func (e *IPAMSuite) TestNodeManagerMinAllocateAndPreallocate(c *check.C) {
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", 1, 10, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)

	node := mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 10)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// Use 9 out of 10 IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 9))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 10)
	c.Assert(node.Stats().UsedIPs, check.Equals, 9)

	// Use 10 out of 10 IPs, PreAllocate 1 must kick in and allocate an additional IP
	mngr.Update(updateCiliumNode(cn, 10))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 11)
	c.Assert(node.Stats().UsedIPs, check.Equals, 10)

	// Release some IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 8))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node2")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 11)
	c.Assert(node.Stats().UsedIPs, check.Equals, 8)
}

// TestNodeManagerReleaseAddress tests PreAllocate, MinAllocate and MaxAboveWatermark
// when release excess IP is enabled
//
// - MinAllocate 15
// - PreAllocate 4
// - MaxAboveWatermark 4
func (e *IPAMSuite) TestNodeManagerReleaseAddress(c *check.C) {
	operatorOption.Config.ExcessIPReleaseDelay = 2
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, true, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", 4, 15, 0)
	cn.Spec.IPAM.MaxAboveWatermark = 4
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 1*time.Second), check.IsNil)

	node := mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 19)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// Use 11 out of 19 IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 11))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 19)
	c.Assert(node.Stats().UsedIPs, check.Equals, 11)

	// Use 19 out of 19 IPs, PreAllocate 4 + MaxAboveWatermark must kick in and allocate 8 additional IPs
	mngr.Update(updateCiliumNode(cn, 19))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 27)
	c.Assert(node.Stats().UsedIPs, check.Equals, 19)

	// Free some IPs, 5 excess IPs appears but only be released at interval based resync, so expect timeout here
	mngr.Update(updateCiliumNode(cn, 10))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 2*time.Second), check.Not(check.IsNil))
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 27)
	c.Assert(node.Stats().UsedIPs, check.Equals, 10)

	// Trigger resync manually, excess IPs should be released down to 18
	// (10 used + 4 prealloc + 4 max-above-watermark)
	// Excess timestamps should be registered after this trigger
	mngr.resyncTrigger.Trigger()

	// Acknowledge release IPs after 3 secs
	time.AfterFunc(3*time.Second, func() {
		// Excess delay duration should have elapsed by now, trigger resync again.
		// IPs should be marked as excess
		mngr.resyncTrigger.Trigger()
		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(node.resource)
		// Fake acknowledge IPs for release like agent would.
		testutils.FakeAcknowledgeReleaseIps(node.resource)
		// Resync one more time to process acknowledgements.
		mngr.resyncTrigger.Trigger()
	})

	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 18)
	c.Assert(node.Stats().UsedIPs, check.Equals, 10)
}

// TestNodeManagerAbortRelease tests aborting IP release handshake if a new allocation on the node results in excess
// being resolved
func (e *IPAMSuite) TestNodeManagerAbortRelease(c *check.C) {
	var wg sync.WaitGroup
	operatorOption.Config.ExcessIPReleaseDelay = 2
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, true, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", 1, 3, 0)
	mngr.Update(cn)
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 1*time.Second), check.IsNil)

	node := mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 3)
	c.Assert(node.Stats().UsedIPs, check.Equals, 0)

	// Use 3 out of 4 IPs, no additional IPs should be allocated
	mngr.Update(updateCiliumNode(cn, 3))
	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 4)
	c.Assert(node.Stats().UsedIPs, check.Equals, 3)

	mngr.Update(updateCiliumNode(node.resource, 2))
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 4)
	c.Assert(node.Stats().UsedIPs, check.Equals, 2)

	// Trigger resync manually, excess IPs should be released down to 3
	// Excess timestamps should be registered after this trigger
	mngr.resyncTrigger.Trigger()
	wg.Add(1)

	// Acknowledge release IPs after 3 secs
	time.AfterFunc(3*time.Second, func() {
		defer wg.Done()
		// Excess delay duration should have elapsed by now, trigger resync again.
		// IPs should be marked as excess
		mngr.resyncTrigger.Trigger()
		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(node.resource)

		c.Assert(len(node.resource.Status.IPAM.ReleaseIPs), check.Equals, 1)

		// Fake acknowledge IPs for release like agent would.
		testutils.FakeAcknowledgeReleaseIps(node.resource)

		// Use up one more IP to make excess = 0
		mngr.Update(updateCiliumNode(node.resource, 3))
		node.poolMaintainer.Trigger()
		// Resync one more time to process acknowledgements.
		mngr.resyncTrigger.Trigger()

		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(node.resource)

		// Verify that the entry for previously marked IP is removed, instead of being set to released state.
		c.Assert(len(node.resource.Status.IPAM.ReleaseIPs), check.Equals, 0)
	})

	c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second), check.IsNil)
	wg.Wait()
	node = mngr.Get("node3")
	c.Assert(node, check.Not(check.IsNil))
	c.Assert(node.Stats().AvailableIPs, check.Equals, 4)
	c.Assert(node.Stats().UsedIPs, check.Equals, 3)
}

type nodeState struct {
	cn           *v2.CiliumNode
	name         string
	instanceName string
}

// TestNodeManagerManyNodes tests IP allocation of 100 nodes across 3 subnets
//
// - MinAllocate 10
// - PreAllocate 1
func (e *IPAMSuite) TestNodeManagerManyNodes(c *check.C) {
	const (
		numNodes    = 100
		minAllocate = 10
	)

	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	state := make([]*nodeState, numNodes)

	for i := range state {
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-testNodeManagerManyNodes-%d", i)}
		s.cn = newCiliumNode(s.name, 1, minAllocate, 0)
		state[i] = s
		mngr.Update(s.cn)
	}

	for _, s := range state {
		c.Assert(testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second), check.IsNil)

		node := mngr.Get(s.name)
		c.Assert(node, check.Not(check.IsNil))
		if node.Stats().AvailableIPs != minAllocate {
			c.Errorf("Node %s allocation mismatch. expected: %d allocated: %d", s.name, minAllocate, node.Stats().AvailableIPs)
			c.Fail()
		}
		c.Assert(node.Stats().UsedIPs, check.Equals, 0)
	}

	// The above check returns as soon as the address requirements are met.
	// The metrics may still be oudated, resync all nodes to update
	// metrics.
	mngr.Resync(context.TODO(), time.Now())

	c.Assert(metricsapi.Nodes("total"), check.Equals, numNodes)
	c.Assert(metricsapi.Nodes("in-deficit"), check.Equals, 0)
	c.Assert(metricsapi.Nodes("at-capacity"), check.Equals, 0)

	c.Assert(metricsapi.AllocatedIPs("available"), check.Equals, numNodes*minAllocate)
	c.Assert(metricsapi.AllocatedIPs("needed"), check.Equals, 0)
	c.Assert(metricsapi.AllocatedIPs("used"), check.Equals, 0)

	c.Assert(metricsapi.ResyncCount(), check.Not(check.Equals), 0)
}

func benchmarkAllocWorker(c *check.C, workers int64, delay time.Duration, rateLimit float64, burst int) {
	am := newAllocationImplementationMock()
	c.Assert(am, check.Not(check.IsNil))
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false)
	c.Assert(err, check.IsNil)
	c.Assert(mngr, check.Not(check.IsNil))

	state := make([]*nodeState, c.N)

	c.ResetTimer()
	for i := range state {
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-benchmarkAllocWorker-%d", i)}
		s.cn = newCiliumNode(s.name, 1, 10, 0)
		state[i] = s
		mngr.Update(s.cn)
	}

restart:
	for _, s := range state {
		if !reachedAddressesNeeded(mngr, s.name, 0) {
			time.Sleep(5 * time.Millisecond)
			goto restart
		}
	}
	c.StopTimer()

}

func (e *IPAMSuite) BenchmarkAllocDelay20Worker1(c *check.C) {
	benchmarkAllocWorker(c, 1, 20*time.Millisecond, 100.0, 4)
}
func (e *IPAMSuite) BenchmarkAllocDelay20Worker10(c *check.C) {
	benchmarkAllocWorker(c, 10, 20*time.Millisecond, 100.0, 4)
}
func (e *IPAMSuite) BenchmarkAllocDelay20Worker50(c *check.C) {
	benchmarkAllocWorker(c, 50, 20*time.Millisecond, 100.0, 4)
}
func (e *IPAMSuite) BenchmarkAllocDelay50Worker1(c *check.C) {
	benchmarkAllocWorker(c, 1, 50*time.Millisecond, 100.0, 4)
}
func (e *IPAMSuite) BenchmarkAllocDelay50Worker10(c *check.C) {
	benchmarkAllocWorker(c, 10, 50*time.Millisecond, 100.0, 4)
}
func (e *IPAMSuite) BenchmarkAllocDelay50Worker50(c *check.C) {
	benchmarkAllocWorker(c, 50, 50*time.Millisecond, 100.0, 4)
}
