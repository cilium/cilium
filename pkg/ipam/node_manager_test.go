// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/defaults"
	metricsmock "github.com/cilium/cilium/pkg/ipam/metrics/mock"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ipamStats "github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
	testipam "github.com/cilium/cilium/pkg/testutils/ipam"
)

var (
	k8sapi = &k8sMock{}
)

const (
	testPoolID               = ipamTypes.PoolID("global")
	testExcessIPReleaseDelay = 2
)

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
	mutex        lock.RWMutex
	allocatedIPs []string
}

func (n *nodeOperationsMock) GetUsedIPWithPrefixes() int {
	return len(n.allocatedIPs)
}

func (n *nodeOperationsMock) UpdatedNode(obj *v2.CiliumNode) {}

func (n *nodeOperationsMock) PopulateStatusFields(resource *v2.CiliumNode) {}

func (n *nodeOperationsMock) CreateInterface(ctx context.Context, allocation *AllocationAction, scopedLog *slog.Logger) (int, string, error) {
	return 0, "operation not supported", fmt.Errorf("operation not supported")
}

func (n *nodeOperationsMock) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *slog.Logger) (
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

func (n *nodeOperationsMock) PrepareIPAllocation(scopedLog *slog.Logger) (*AllocationAction, error) {
	n.allocator.mutex.RLock()
	defer n.allocator.mutex.RUnlock()
	return &AllocationAction{
		PoolID: testPoolID,
		IPv4: IPAllocationAction{
			AvailableForAllocation: n.allocator.poolSize - n.allocator.allocatedIPs,
		},
	}, nil
}

func (n *nodeOperationsMock) AllocateIPs(ctx context.Context, allocation *AllocationAction) error {
	n.mutex.Lock()
	n.allocator.mutex.Lock()
	n.allocator.allocatedIPs += allocation.IPv4.AvailableForAllocation
	for range allocation.IPv4.AvailableForAllocation {
		n.allocator.ipGenerator++
		n.allocatedIPs = append(n.allocatedIPs, fmt.Sprintf("%d", n.allocator.ipGenerator))
	}
	n.allocator.mutex.Unlock()
	n.mutex.Unlock()
	return nil
}

func (n *nodeOperationsMock) AllocateStaticIP(ctx context.Context, staticIPTags ipamTypes.Tags) (string, error) {
	return "", nil
}

func (n *nodeOperationsMock) PrepareIPRelease(excessIPs int, scopedLog *slog.Logger) *ReleaseAction {
	n.mutex.RLock()
	excessIPs = min(excessIPs, len(n.allocatedIPs))
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
			n.allocatedIPs = slices.Delete(n.allocatedIPs, i, i+1)
			n.allocator.allocatedIPs--
			return nil
		}
	}
	return fmt.Errorf("IP %s not found", ip)
}

func (n *nodeOperationsMock) ReleaseIPPrefixes(ctx context.Context, release *ReleaseAction) error {
	// no-op stub for tests
	return nil
}

func (n *nodeOperationsMock) ReleaseIPs(ctx context.Context, release *ReleaseAction) error {
	for _, ipToDelete := range release.IPsToRelease {
		if err := n.releaseIP(ipToDelete); err != nil {
			return fmt.Errorf("unable to release IP %s: %w", ipToDelete, err)
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

func TestGetNodeNames(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node1", 0, 0, 0)
	mngr.Upsert(node1)

	names := mngr.GetNames()
	require.Len(t, names, 1)
	require.Equal(t, "node1", names[0])

	mngr.Upsert(newCiliumNode("node2", 0, 0, 0))

	names = mngr.GetNames()
	require.Len(t, names, 2)

	mngr.Delete(node1)

	names = mngr.GetNames()
	require.Len(t, names, 1)
	require.Equal(t, "node2", names[0])
}

func TestNodeManagerGet(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
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
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metrics, 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	node1 := newCiliumNode("node-foo", 0, 0, 0)
	mngr.Upsert(node1)

	require.NotNil(t, mngr.Get("node-foo"))
	require.Nil(t, mngr.Get("node2"))

	mngr.Resync(t.Context(), time.Now())
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
func TestNodeManagerDefaultAllocation(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node1", 8, 0, 0)
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node := mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 8, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 7 out of 8 IPs
	mngr.Upsert(updateCiliumNode(cn, 7))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node1", 0) }, 5*time.Second))

	node = mngr.Get("node1")
	require.NotNil(t, node)
	require.Equal(t, 15, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 7, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerMinAllocate20 tests MinAllocate without PreAllocate
//
// - MinAllocate 10
// - PreAllocate -1
func TestNodeManagerMinAllocate20(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node wait for IPs to become available
	cn := newCiliumNode("node2", -1, 10, 0)
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// 10 available, 8 used
	mngr.Upsert(updateCiliumNode(cn, 8))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 8, node.Stats().IPv4.UsedIPs)

	// Change MinAllocate to 20
	mngr.Upsert(newCiliumNode("node2", 0, 20, 8))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

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
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node2", 1, 10, 0)
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))

	node := mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 9 out of 10 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 9))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 10, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 9, node.Stats().IPv4.UsedIPs)

	// Use 10 out of 10 IPs, PreAllocate 1 must kick in and allocate an additional IP
	mngr.Upsert(updateCiliumNode(cn, 10))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
	node = mngr.Get("node2")
	require.NotNil(t, node)
	require.Equal(t, 11, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)

	// Release some IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 8))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node2", 0) }, 5*time.Second))
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
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, true, testExcessIPReleaseDelay, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", 4, 15, 0)
	cn.Spec.IPAM.MaxAboveWatermark = 4
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 1*time.Second))

	node := mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 19, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 11 out of 19 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 11))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 19, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 11, node.Stats().IPv4.UsedIPs)

	// Use 19 out of 19 IPs, PreAllocate 4 + MaxAboveWatermark must kick in and allocate 8 additional IPs
	mngr.Upsert(updateCiliumNode(cn, 19))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 27, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 19, node.Stats().IPv4.UsedIPs)

	// Free some IPs, 5 excess IPs appears but only be released at interval based resync, so expect timeout here
	mngr.Upsert(updateCiliumNode(cn, 10))
	require.Error(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 2*time.Second))
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

	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 19, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 10, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerAbortRelease tests aborting IP release handshake if a new allocation on the node results in excess
// being resolved
func TestNodeManagerAbortRelease(t *testing.T) {
	var wg sync.WaitGroup
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, true, testExcessIPReleaseDelay, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node3", 1, 3, 0)
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 1*time.Second))

	node := mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 3, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 3 out of 4 IPs, no additional IPs should be allocated
	mngr.Upsert(updateCiliumNode(cn, 3))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
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

		require.Len(t, node.resource.Status.IPAM.ReleaseIPs, 1)

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
		require.Empty(t, node.resource.Status.IPAM.ReleaseIPs)
	})

	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node3", 0) }, 5*time.Second))
	wg.Wait()
	node = mngr.Get("node3")
	require.NotNil(t, node)
	require.Equal(t, 4, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 3, node.Stats().IPv4.UsedIPs)
}

// TestNodeManagerAbortReleaseIPReassignment tests a scenario where:
// 1. An IP is released and marked as released in status.ipam.release-ips
// 2. The IP is removed from spec.ipam.pool
// 3. Before being removed from status.ipam.release-ips, the same IP is reassigned to the pool (ie. AWS ENI in the case of AWS ENI IPAM)
// 4. The IP is no longer considered excess, so the release handshake is aborted and the IP is deleted from status.ipam.release-ips
func TestNodeManagerAbortReleaseIPReassignment(t *testing.T) {
	am := newAllocationImplementationMock()
	require.NotNil(t, am)
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsmock.NewMockMetrics(), 10, true, testExcessIPReleaseDelay, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	// Announce node, wait for IPs to become available
	cn := newCiliumNode("node4", 1, 3, 0)
	mngr.Upsert(cn)
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node4", 0) }, 5*time.Second))

	node := mngr.Get("node4")
	require.NotNil(t, node)
	require.Equal(t, 3, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 0, node.Stats().IPv4.UsedIPs)

	// Use 3 out of 4 IPs
	mngr.Upsert(updateCiliumNode(cn, 3))
	require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, "node4", 0) }, 5*time.Second))

	node = mngr.Get("node4")
	require.NotNil(t, node)
	require.Equal(t, 4, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 3, node.Stats().IPv4.UsedIPs)

	// Release one IP
	mngr.Upsert(updateCiliumNode(node.resource, 2))

	node = mngr.Get("node4")
	require.NotNil(t, node)
	require.Equal(t, 4, node.Stats().IPv4.AvailableIPs)
	require.Equal(t, 2, node.Stats().IPv4.UsedIPs)

	node.instanceSync.Trigger()

	// This is the key IP that will be released and later reassigned
	var releasedIP string

	// Wait for the IP to be marked as excess for longer than the ExcessIPReleaseDelay
	require.Eventually(t, func() bool {
		node.mutex.Lock()
		defer node.mutex.Unlock()

		if len(node.ipv4Alloc.ipsMarkedForRelease) == 0 {
			return false
		}

		for _, ts := range node.ipv4Alloc.ipsMarkedForRelease {
			if ts.Add(time.Duration(testExcessIPReleaseDelay) * time.Second).Before(time.Now()) {
				return true
			}
		}

		return false
	}, 10*time.Second, time.Second)

	// Mark IP as excess
	node.instanceSync.Trigger()

	// Wait for maintenance action to identify the IP to release
	require.Eventually(t, func() bool {
		a, err := node.determineMaintenanceAction()
		if err != nil || a == nil || a.release == nil || len(a.release.IPsToRelease) == 0 {
			return false
		}

		// Get the IP being released
		releasedIP = a.release.IPsToRelease[0]
		return releasedIP != ""
	}, 10*time.Second, time.Second)

	// Actually run the IP maintenance process to mark the IP for release
	err = node.MaintainIPPool(context.Background())
	require.NoError(t, err)

	node.PopulateIPReleaseStatus(node.resource)

	node.mutex.Lock()

	// Verify it's marked for release in the CiliumNode resource
	require.Contains(t, node.resource.Status.IPAM.ReleaseIPs, releasedIP)
	require.Equal(t, ipamOption.IPAMMarkForRelease, string(node.resource.Status.IPAM.ReleaseIPs[releasedIP]))

	// Fake acknowledge IP for release like agent would
	testipam.FakeAcknowledgeReleaseIps(node.resource)

	node.mutex.Unlock()

	// Run maintenance process again to process the acknowledgment
	err = node.MaintainIPPool(context.Background())

	// Handle the case where the MaintainIPPool trigger runs first
	expectedErrorStr := fmt.Sprintf("unable to release IP %s: IP %s not found", releasedIP, releasedIP)
	require.Condition(t, func() bool {
		return err == nil || err.Error() == expectedErrorStr
	})

	// Resync one more time to process acknowledgements.
	node.instanceSync.Trigger()

	require.Eventually(t, func() bool {
		node.mutex.Lock()
		defer node.mutex.Unlock()

		status, exists := node.resource.Status.IPAM.ReleaseIPs[releasedIP]
		return exists && string(status) == ipamOption.IPAMReadyForRelease
	}, 10*time.Second, time.Second)

	node.mutex.Lock()

	// Now simulate the operator releasing the IP and marking it as released
	delete(node.resource.Spec.IPAM.Pool, releasedIP)
	node.resource.Status.IPAM.ReleaseIPs[releasedIP] = ipamOption.IPAMReleased

	// Also mark it as released in the internal ipReleaseStatus map
	node.ipv4Alloc.ipReleaseStatus[releasedIP] = ipamOption.IPAMReleased

	// Normally at this point, the agent would see the IP is released and remove it from Status.IPAM.ReleaseIPs
	// But before that happens, simulate the IP being reassigned back to the pool
	if node.resource.Spec.IPAM.Pool == nil {
		node.resource.Spec.IPAM.Pool = ipamTypes.AllocationMap{}
	}
	node.resource.Spec.IPAM.Pool[releasedIP] = ipamTypes.AllocationIP{Resource: "eni-test"}

	node.mutex.Unlock()

	node.ops.AllocateIPs(context.Background(), &AllocationAction{
		IPv4: IPAllocationAction{
			AvailableForAllocation: 1,
		},
	})

	node.poolMaintainer.Trigger()
	node.instanceSync.Trigger()

	require.Eventually(t, func() bool {
		node.PopulateIPReleaseStatus(node.resource)

		node.mutex.Lock()
		defer node.mutex.Unlock()

		_, inReleaseStatus := node.ipv4Alloc.ipReleaseStatus[releasedIP]
		_, inMarkedForRelease := node.ipv4Alloc.ipsMarkedForRelease[releasedIP]
		_, inReleaseIPs := node.resource.Status.IPAM.ReleaseIPs[releasedIP]

		return !inReleaseStatus && !inMarkedForRelease && !inReleaseIPs
	}, 10*time.Second, time.Second)

	// Wait for the InstanceSync job to finish and update the node stats
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		node = mngr.Get("node4")
		assert.NotNil(c, node)
		assert.Equal(c, 4, node.Stats().IPv4.AvailableIPs)
		assert.Equal(c, 2, node.Stats().IPv4.UsedIPs)
	}, 15*time.Second, time.Second, "AvailableIPs and UsedIPs count did not update")
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
	mngr, err := NewNodeManager(hivetest.Logger(t), am, k8sapi, metricsapi, 10, false, 0, false)
	require.NoError(t, err)
	require.NotNil(t, mngr)

	state := make([]*nodeState, numNodes)

	for i := range state {
		s := &nodeState{name: fmt.Sprintf("node%d", i), instanceName: fmt.Sprintf("i-testNodeManagerManyNodes-%d", i)}
		s.cn = newCiliumNode(s.name, 1, minAllocate, 0)
		state[i] = s
		mngr.Upsert(s.cn)
	}

	for _, s := range state {
		require.NoError(t, testutils.WaitUntil(func() bool { return reachedAddressesNeeded(mngr, s.name, 0) }, 5*time.Second))

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
	mngr.Resync(t.Context(), time.Now())

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
	mngr, err := NewNodeManager(hivetest.Logger(b), am, k8sapi, metricsmock.NewMockMetrics(), 10, false, 0, false)
	require.NoError(b, err)
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
