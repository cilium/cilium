// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/defaults"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	"github.com/cilium/cilium/pkg/ipam/option"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/testutils"
	testipam "github.com/cilium/cilium/pkg/testutils/ipam"
)

var (
	k8sapi = &k8sMock{}
)

const testPoolID = ipamTypes.PoolID("global")

type allocationImplementationMock struct {
	// mutex protects all fields of this structure
	mutex          lock.RWMutex
	poolSize       int
	v6PoolSize     int
	allocatedIPs   int
	allocatedIPv6s int
	ipGenerator    int
	ipv6Generator  int
}

func newAllocationImplementationMock() *allocationImplementationMock {
	return &allocationImplementationMock{
		poolSize:   2048,
		v6PoolSize: 2048,
	}
}

func (a *allocationImplementationMock) CreateNode(obj *v2.CiliumNode, node *Node) NodeOperations {
	return &nodeOperationsMock{allocator: a}
}

func (a *allocationImplementationMock) GetPoolQuota() ipamTypes.PoolQuotaMap {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	return ipamTypes.PoolQuotaMap{
		testPoolID: ipamTypes.PoolQuota{
			AvailableIPs:   a.poolSize - a.allocatedIPs,
			AvailableIPv6s: a.v6PoolSize - a.allocatedIPv6s,
		},
	}
}

func (a *allocationImplementationMock) Resync(ctx context.Context) time.Time {
	return time.Now()
}

func (a *allocationImplementationMock) InstanceSync(ctx context.Context, instanceID string) time.Time {
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
	mutex          lock.RWMutex
	allocatedIPs   []string
	allocatedIPv6s []string
}

func (n *nodeOperationsMock) GetUsedIPWithPrefixes(family Family) int {
	if family == IPv6 {
		return len(n.allocatedIPv6s)
	}
	return len(n.allocatedIPs)
}

func (n *nodeOperationsMock) UpdatedNode(obj *v2.CiliumNode) {}

func (n *nodeOperationsMock) PopulateStatusFields(resource *v2.CiliumNode) {}

func (n *nodeOperationsMock) CreateInterface(ctx context.Context, allocation *AllocationAction, scopedLog *logrus.Entry, family Family) (int, string, error) {
	return 0, "operation not supported", fmt.Errorf("operation not supported")
}

func (n *nodeOperationsMock) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry, family Family) (
	ipamTypes.AllocationMap,
	ipamStats.InterfaceStats,
	error) {
	var stats ipamStats.InterfaceStats
	available := ipamTypes.AllocationMap{}
	n.mutex.RLock()
	if family == IPv4 {
		for _, ip := range n.allocatedIPs {
			available[ip] = ipamTypes.AllocationIP{}
		}
	} else {
		for _, ip := range n.allocatedIPv6s {
			available[ip] = ipamTypes.AllocationIP{}
		}
	}
	n.mutex.RUnlock()
	return available, stats, nil
}

func (n *nodeOperationsMock) PrepareIPAllocation(scopedLog *logrus.Entry, family Family) (*AllocationAction, error) {
	n.allocator.mutex.RLock()
	defer n.allocator.mutex.RUnlock()
	alloc := &AllocationAction{PoolID: testPoolID}
	if family == IPv4 {
		alloc.IPv4 = IPAllocationAction{AvailableForAllocation: n.allocator.poolSize - n.allocator.allocatedIPs}
	} else {
		alloc.IPv6 = IPAllocationAction{AvailableForAllocation: n.allocator.v6PoolSize - n.allocator.allocatedIPv6s}
	}
	return alloc, nil
}

func (n *nodeOperationsMock) AllocateIPs(ctx context.Context, allocation *AllocationAction, family Family) error {
	n.mutex.Lock()
	n.allocator.mutex.Lock()
	if family == IPv4 {
		n.allocator.allocatedIPs += allocation.IPv4.AvailableForAllocation
		for i := 0; i < allocation.IPv4.AvailableForAllocation; i++ {
			n.allocator.ipGenerator++
			n.allocatedIPs = append(n.allocatedIPs, fmt.Sprintf("%d", n.allocator.ipGenerator))
		}
	} else {
		n.allocator.allocatedIPv6s += allocation.IPv6.AvailableForAllocation
		for i := 0; i < allocation.IPv6.AvailableForAllocation; i++ {
			n.allocator.ipv6Generator++
			n.allocatedIPv6s = append(n.allocatedIPv6s, fmt.Sprintf("%d", n.allocator.ipv6Generator))
		}
	}
	n.allocator.mutex.Unlock()
	n.mutex.Unlock()
	return nil
}

func (n *nodeOperationsMock) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry, family Family) *ReleaseAction {
	n.mutex.RLock()
	r := &ReleaseAction{PoolID: testPoolID}
	if family == IPv4 {
		excessIPs = math.IntMin(excessIPs, len(n.allocatedIPs))
		for i := 1; i <= excessIPs; i++ {
			// Release from the end of slice to avoid releasing used IPs
			releaseIndex := len(n.allocatedIPs) - (excessIPs + i - 1)
			r.IPsToRelease = append(r.IPsToRelease, n.allocatedIPs[releaseIndex])
		}
	} else {
		excessIPs = math.IntMin(excessIPs, len(n.allocatedIPv6s))
		for i := 1; i <= excessIPs; i++ {
			// Release from the end of slice to avoid releasing used IPs
			releaseIndex := len(n.allocatedIPv6s) - (excessIPs + i - 1)
			r.IPv6sToRelease = append(r.IPv6sToRelease, n.allocatedIPv6s[releaseIndex])
		}
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
			return fmt.Errorf("unable to release IP %s: %w", ipToDelete, err)
		}
	}
	return nil
}

func (n *nodeOperationsMock) GetMaximumAllocatableIP(family Family) int {
	max := 0
	if family == IPv6 {
		max = option.ENIPDBlockSizeIPv6
	}
	return max
}

func (n *nodeOperationsMock) GetMinimumAllocatableIP(family Family) int {
	if family == IPv4 {
		return defaults.IPAMPreAllocation
	}
	return defaults.IPAMIPv6PreAllocation
}

func (n *nodeOperationsMock) IsPrefixDelegated(family Family) bool {
	return false
}

func TestGetNodeNames(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node1", 0, 0, 0)
	mngr.Upsert(node1)

	names := mngr.GetNames()
	require.Equal(t, 1, len(names))
	require.Equal(t, "node1", names[0])

	mngr.Upsert(newCiliumNode("node2", 0, 0, 0))

	names = mngr.GetNames()
	require.Equal(t, 2, len(names))

	mngr.Delete(node1)

	names = mngr.GetNames()
	require.Equal(t, 1, len(names))
	require.Equal(t, "node2", names[0])
}

func TestNodeManagerGet(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node1", 0, 0, 0)
	mngr.Upsert(node1)

	require.NotNil(t, mngr.Get("node1"))
	require.Nil(t, mngr.Get("node2"))

	mngr.Delete(node1)
	require.Nil(t, mngr.Get("node1"))
	require.Nil(t, mngr.Get("node2"))
}

func TestNodeManagerDelete(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	metrics := metricsmock.NewMockMetrics()
	mngr, err := NewNodeManager(am, k8sapi, metrics, 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node-foo", 0, 0, 0)
	mngr.Upsert(node1)

	require.NotNil(t, mngr.Get("node-foo"))
	require.Nil(t, mngr.Get("node2"))

	mngr.Resync(context.Background(), time.Now())
	avail, used, needed := metrics.GetPerNodeMetrics("node-foo")
	require.NotNil(t, avail)
	require.NotNil(t, used)
	require.NotNil(t, needed)
	mngr.Delete(node1)
	// Following a node Delete, we expect the per-node metrics for that Node to be
	// deleted.
	avail, used, needed = metrics.GetPerNodeMetrics("node-foo")
	require.Nil(t, avail)
	require.Nil(t, used)
	require.Nil(t, needed)
	require.Nil(t, mngr.Get("node-foo"))
	require.Nil(t, mngr.Get("node2"))
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

func newIPv6CiliumNode(node string, preAllocate, minAllocate, used int) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				IPv6Pool:        ipamTypes.AllocationMap{},
				IPv6PreAllocate: preAllocate,
				IPv6MinAllocate: minAllocate,
			},
		},
		Status: v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				IPv6Used:     ipamTypes.AllocationMap{},
				ReleaseIPv6s: map[string]ipamTypes.IPReleaseStatus{},
			},
		},
	}

	updateCiliumIPv6Node(cn, used)

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

func updateCiliumIPv6Node(cn *v2.CiliumNode, used int) *v2.CiliumNode {
	cn.Spec.IPAM.IPv6Pool = ipamTypes.AllocationMap{}
	for i := 1; i <= used; i++ {
		cn.Spec.IPAM.IPv6Pool[fmt.Sprintf("2001:db8::%d", i)] = ipamTypes.AllocationIP{Resource: "foo"}
	}

	cn.Status.IPAM.IPv6Used = ipamTypes.AllocationMap{}
	for ip, ipAllocation := range cn.Spec.IPAM.IPv6Pool {
		if used > 0 {
			delete(cn.Spec.IPAM.IPv6Pool, ip)
			cn.Status.IPAM.IPv6Used[ip] = ipAllocation
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

func reachedIPv6AddressesNeeded(mngr *NodeManager, nodeName string, needed int) (success bool) {
	if node := mngr.Get(nodeName); node != nil {
		success = node.GetNeededIPv6Addresses() == needed
	}
	return
}

// TestNodeManagerDefaultAllocation tests allocation with default parameters
//
// - MinAllocate 0
// - PreAllocate 8
func TestNodeManagerDefaultAllocation(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", 8, 0, 0)
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 7 out of 8 IPs
	mngr.Upsert(updateCiliumNode(cn, 7))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 15, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 7, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerDefaultIPv6Allocation tests IPv6 allocation with default parameters
//
// - MinAllocate 0
// - PreAllocate 32
func TestNodeManagerDefaultIPv6Allocation(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, true)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	nodeName := "node-ipv6-defaults"
	cn := newIPv6CiliumNode(nodeName, 32, 0, 0)
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedIPv6AddressesNeeded(mngr, nodeName, 0) }, 5*time.Second))

	node := mngr.Get(nodeName)
	require.NotNil(t, node)
	require.Equal(t, 32, node.Stats().IPv6.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv6.UsedIPs)

	// Use 31 of 32 IPs
	cn = updateCiliumIPv6Node(cn, 31)
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedIPv6AddressesNeeded(mngr, nodeName, 0) }, 5*time.Second))

	node = mngr.Get(nodeName)
	require.NotNil(t, node)
	require.Equal(t, 63, node.Stats().IPv6.AvailableIPs)
	require.Equal(t, 31, node.Stats().IPv6.UsedIPs)
}

// TestNodeManagerMinAllocate20 tests MinAllocate without PreAllocate
//
// - MinAllocate 10
// - PreAllocate -1
func TestNodeManagerMinAllocate20(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node2", -1, 10, 0)
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// 10 available, 8 used
	mngr.Upsert(updateCiliumNode(cn, 8))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)

	// Change MinAllocate to 20
	mngr.Upsert(newCiliumNode("node2", 0, 20, 8))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)
	require.Equal(t, 20, node.Stats().IPv4.AvailableIPs)
}

// TestNodeManagerMinAllocateAndPreallocate tests MinAllocate in combination with PreAllocate
//
// - MinAllocate 10
// - PreAllocate 1
func TestNodeManagerMinAllocateAndPreallocate(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", 1, 10, 0)
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 9 out of 10 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 9))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 9, node.Stats().IPv4.UsedIPs)

	// Use 10 out of 10 IPs, PreAllocate 1 must kick in and allocate an additional IP
	mngr.Upsert(updateCiliumNode(cn, 10))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 11, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)

	// Release some IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 8))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 11, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerReleaseAddress tests PreAllocate, MinAllocate and MaxAboveWatermark
// when release excess IP is enabled
//
// - MinAllocate 15
// - PreAllocate 4
// - MaxAboveWatermark 4
func TestNodeManagerReleaseAddress(t *testing.T) {
	operatorOption.Config.ExcessIPReleaseDelay = 2
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, true, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", 4, 15, 0)
	cn.Spec.IPAM.MaxAboveWatermark = 4
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 1*time.Second))

	node := mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 19, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 11 out of 19 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 11))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 19, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 11, node.Stats().IPv4.UsedIPs)

	// Use 19 out of 19 IPs, PreAllocate 4 + MaxAboveWatermark must kick in and allocate 8 additional IPs
	mngr.Upsert(updateCiliumNode(cn, 19))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 27, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 19, node.Stats().IPv4.UsedIPs)

	// Free some IPs, 5 excess IPs appears but only be released at interval based resync, so expect timeout here
	mngr.Upsert(updateCiliumNode(cn, 10))
	require.NotNil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 2*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 27, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)

	// Trigger resync manually, excess IPs should be released down to 18
	// (10 used + 4 prealloc + 4 max-above-watermark)
	// Excess timestamps should be registered after this trigger
	node.instanceSync.Trigger()

	// Acknowledge release IPs after 3 secs
	time.AfterFunc(3*time.Second, func() {
		// Excess delay duration should have elapsed by now, trigger resync again.
		// IPs should be marked as excess
		node.instanceSync.Trigger()
		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(node.resource)
		// Fake acknowledge IPs for release like agent would.
		testipam.FakeAcknowledgeReleaseIps(node.resource)
		// Resync one more time to process acknowledgements.
		node.instanceSync.Trigger()
	})

	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 19, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerAbortRelease tests aborting IP release handshake if a new allocation on the node results in excess
// being resolved
func TestNodeManagerAbortRelease(t *testing.T) {
	var wg sync.WaitGroup
	operatorOption.Config.ExcessIPReleaseDelay = 2
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, true, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", 1, 3, 0)
	mngr.Upsert(cn)
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 1*time.Second))

	node := mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 3, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 3 out of 4 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 3))
	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 4, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 3, node.Stats().IPv4.UsedIPs)

	mngr.Upsert(updateCiliumNode(node.resource, 2))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 4, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 2, node.Stats().IPv4.UsedIPs)

	// Trigger resync manually, excess IPs should be released down to 3
	// Excess timestamps should be registered after this trigger
	node.instanceSync.Trigger()
	wg.Add(1)

	// Acknowledge release IPs after 3 secs
	time.AfterFunc(3*time.Second, func() {
		defer wg.Done()
		// Excess delay duration should have elapsed by now, trigger resync again.
		// IPs should be marked as excess
		node.instanceSync.Trigger()
		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(node.resource)

		require.Equal(t, 1, len(node.resource.Status.IPAM.ReleaseIPs))

		// Fake acknowledge IPs for release like agent would.
		testipam.FakeAcknowledgeReleaseIps(node.resource)

		// Use up one more IP to make excess = 0
		mngr.Upsert(updateCiliumNode(node.resource, 3))
		node.poolMaintainer.Trigger()
		// Resync one more time to process acknowledgements.
		node.instanceSync.Trigger()

		time.Sleep(1 * time.Second)
		node.PopulateIPReleaseStatus(node.resource)

		// Verify that the entry for previously marked IP is removed, instead of being set to released state.
		require.Equal(t, 0, len(node.resource.Status.IPAM.ReleaseIPs))
	})

	require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	wg.Wait()
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 4, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 3, node.Stats().IPv4.UsedIPs)
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
func TestNodeManagerManyNodes(t *testing.T) {
	const (
		numNodes    = 100
		minAllocate = 10
	)

	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	metricsapi := metricsmock.NewMockMetrics()
	mngr, err := NewNodeManager(am, k8sapi, metricsapi, 10, false, false, false)
	require.Nil(t, err)
	require.NotNil(t, mngr)

	state := make([]*nodeState, numNodes)

	for i := range state {
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-testNodeManagerManyNodes-%d", i)}
		s.cn = newCiliumNode(s.name, 1, minAllocate, 0)
		state[i] = s
		mngr.Upsert(s.cn)
	}

	for _, s := range state {
		require.Nil(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second))

		node := mngr.Get(s.name)
		require.NotNil(t, node)
		if node.Stats().IPv4.AvailableIPs != minAllocate {
			t.Errorf("Node %s allocation mismatch. expected: %d allocated: %d", s.name, minAllocate, node.Stats().IPv4.AvailableIPs)
			t.Fail()
		}
		require.Equal(t, 0, node.Stats().IPv4.UsedIPs)
	}

	// The above check returns as soon as the address requirements are met.
	// The metrics may still be oudated, resync all nodes to update
	// metrics.
	mngr.Resync(context.TODO(), time.Now())

	require.Equal(t, numNodes, metricsapi.Nodes("total"))
	require.Equal(t, 0, metricsapi.Nodes("in-deficit"))
	require.Equal(t, 0, metricsapi.Nodes("at-capacity"))

	require.Equal(t, numNodes*minAllocate, metricsapi.AllocatedIPs("available"))
	require.Equal(t, 0, metricsapi.AllocatedIPs("needed"))
	require.Equal(t, 0, metricsapi.AllocatedIPs("used"))

	require.NotEqual(t, 0, metricsapi.ResyncCount())
}

func benchmarkAllocWorker(b *testing.B, workers int64, delay time.Duration, rateLimit float64, burst int) {
	am := newAllocationImplementationMock()
	require.NotNil(b, am)
	mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, false)
	require.Nil(b, err)
	require.NotNil(b, mngr)

	state := make([]*nodeState, b.N)

	b.ResetTimer()
	for i := range state {
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-benchmarkAllocWorker-%d", i)}
		s.cn = newCiliumNode(s.name, 1, 10, 0)
		state[i] = s
		mngr.Upsert(s.cn)
	}

restart:
	for _, s := range state {
		if !reachedAddressesNeeded(mngr, s.name, 0) {
			time.Sleep(5 * time.Millisecond)
			goto restart
		}
	}
	b.StopTimer()

}

func BenchmarkAllocDelay20Worker1(b *testing.B) {
	benchmarkAllocWorker(b, 1, 20*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay20Worker10(b *testing.B) {
	benchmarkAllocWorker(b, 10, 20*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay20Worker50(b *testing.B) {
	benchmarkAllocWorker(b, 50, 20*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay50Worker1(b *testing.B) {
	benchmarkAllocWorker(b, 1, 50*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay50Worker10(b *testing.B) {
	benchmarkAllocWorker(b, 10, 50*time.Millisecond, 100.0, 4)
}
func BenchmarkAllocDelay50Worker50(b *testing.B) {
	benchmarkAllocWorker(b, 50, 50*time.Millisecond, 100.0, 4)
}

func TestGetNodesByIPWatermarkLocked(t *testing.T) {
	tests := map[string]struct {
		setupNodes    func(mngr *NodeManager)
		expectedOrder []string
		ipv6Enabled   bool
	}{
		"ipv4 nodes": {
			setupNodes: func(mngr *NodeManager) {
				mngr.Upsert(newCiliumNode("node1", 2, 0, 0)) // Node requiring 2 IPv4 addresses
				mngr.Upsert(newCiliumNode("node2", 1, 0, 0)) // Node requiring 1 IPv4 addresses
				mngr.Upsert(newCiliumNode("node3", 3, 0, 0)) // Node requiring 3 IPv4 addresses
			},
			expectedOrder: []string{"node3", "node1", "node2"},
			ipv6Enabled:   false,
		},
		"ipv6 nodes": {
			setupNodes: func(mngr *NodeManager) {
				mngr.ipv6PrefixDelegation = true
				mngr.Upsert(newIPv6CiliumNode("node4", 2, 0, 0)) // Node requiring 2 IPv6 addresses
				mngr.Upsert(newIPv6CiliumNode("node5", 1, 0, 0)) // Node requiring 1 IPv6 addresses
				mngr.Upsert(newIPv6CiliumNode("node6", 3, 0, 0)) // Node requiring 3 IPv6 addresses
			},
			expectedOrder: []string{"node6", "node4", "node5"},
			ipv6Enabled:   true,
		},
	}

	for name, tt := range tests {
		t.Logf("Test case: %s", name)
		am := newAllocationImplementationMock()
		require.NotNil(t, am)
		mngr, err := NewNodeManager(am, k8sapi, metricsmock.NewMockMetrics(), 10, false, false, tt.ipv6Enabled)
		require.Nil(t, err)
		require.NotNil(t, mngr)

		tt.setupNodes(mngr)

		result := mngr.GetNodesByIPWatermarkLocked()

		// Convert result to node names for easier assertion
		nodeNames := make([]string, len(result))
		for i, node := range result {
			nodeNames[i] = node.name
		}

		require.Equal(t, tt.expectedOrder, nodeNames)
	}
}
