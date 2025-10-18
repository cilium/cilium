// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

type k8sNodeMock struct {
	OnUpdate       func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error)
	OnUpdateStatus func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error)
	OnGet          func(node string) (*v2.CiliumNode, error)
	OnCreate       func(n *v2.CiliumNode) (*v2.CiliumNode, error)
}

func (k *k8sNodeMock) Update(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnUpdate != nil {
		return k.OnUpdate(origNode, node)
	}
	panic("d.Update should not be called!")
}

func (k *k8sNodeMock) UpdateStatus(origNode, node *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnUpdateStatus != nil {
		return k.OnUpdateStatus(origNode, node)
	}
	panic("d.UpdateStatus should not be called!")
}

func (k *k8sNodeMock) Get(node string) (*v2.CiliumNode, error) {
	if k.OnGet != nil {
		return k.OnGet(node)
	}
	panic("d.Get should not be called!")
}

func (k *k8sNodeMock) Create(n *v2.CiliumNode) (*v2.CiliumNode, error) {
	if k.OnCreate != nil {
		return k.OnCreate(n)
	}
	panic("d.Create should not be called!")
}

type mockArgs struct {
	oldNode *v2.CiliumNode
	newNode *v2.CiliumNode
}

type mockResult struct {
	node *v2.CiliumNode
	err  error
}

func TestNodeHandler(t *testing.T) {
	backend := NewPoolAllocator(hivetest.Logger(t))
	err := backend.UpsertPool("default", []string{"10.0.0.0/8"}, 24, nil, 0)
	assert.NoError(t, err)

	onUpdateArgs := make(chan mockArgs)
	onUpdateResult := make(chan mockResult)

	onUpdateStatusArgs := make(chan mockArgs)
	onUpdateStatusResult := make(chan mockResult)

	onGetArgs := make(chan string)
	onGetResult := make(chan mockResult)
	nodeUpdater := &k8sNodeMock{
		OnUpdate: func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
			onUpdateArgs <- mockArgs{oldNode, newNode}
			r := <-onUpdateResult
			return r.node, r.err
		},
		OnUpdateStatus: func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
			onUpdateStatusArgs <- mockArgs{oldNode, newNode}
			r := <-onUpdateStatusResult
			return r.node, r.err
		},
		OnGet: func(node string) (*v2.CiliumNode, error) {
			onGetArgs <- node
			r := <-onGetResult
			return r.node, r.err
		},
	}
	nh := NewNodeHandler(hivetest.Logger(t), backend, nodeUpdater)

	// wait 1ms instead of default 1s base duration in unit tests
	nh.controllerErrorRetryBaseDuration = 1 * time.Millisecond

	nh.Upsert(&v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool:   "default",
							Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16},
						},
					},
				},
			},
		},
	})

	// Tests: Node should only be updated after Resync
	select {
	case <-onUpdateArgs:
		t.Fatal("Update should not have be called before Resync")
	default:
	}
	nh.Resync(t.Context(), time.Time{})

	node1Update := <-onUpdateArgs
	assert.Equal(t, "node1", node1Update.newNode.Name)
	assert.Len(t, node1Update.newNode.Spec.IPAM.Pools.Allocated, 1)
	assert.Equal(t, "default", node1Update.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	onUpdateResult <- mockResult{node: node1Update.newNode}

	// Tests: Attempt to occupy already in-use CIDR from node1
	nh.Upsert(&v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool:   "default",
							Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16},
						},
					},
					Allocated: node1Update.newNode.Spec.IPAM.Pools.Allocated,
				},
			},
		},
	})
	node2Update := <-onUpdateArgs
	assert.Equal(t, "node2", node2Update.newNode.Name)
	assert.Len(t, node2Update.newNode.Spec.IPAM.Pools.Allocated, 1)
	assert.Equal(t, "default", node2Update.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	assert.NotEqual(t, node1Update.newNode.Spec.IPAM.Pools.Allocated[0], node2Update.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	onUpdateResult <- mockResult{node: node2Update.newNode}

	node2UpdateStatus := <-onUpdateStatusArgs
	assert.Equal(t, "node2", node2UpdateStatus.newNode.Name)
	assert.Contains(t, node2Update.newNode.Status.IPAM.OperatorStatus.Error, "unable to reuse from pool default")
	onUpdateStatusResult <- mockResult{node: node2Update.newNode}

	// wait for the controller to retry, this time we reject the update with a conflict error
	node2Update = <-onUpdateArgs
	assert.Equal(t, "node2", node2Update.newNode.Name)
	assert.Len(t, node2Update.newNode.Spec.IPAM.Pools.Allocated, 1)
	assert.Equal(t, "default", node2Update.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	ciliumNodeSchema := schema.GroupResource{Group: v2.CustomResourceDefinitionGroup, Resource: v2.CNKindDefinition}
	conflictErr := k8sErrors.NewConflict(ciliumNodeSchema, "node2", errors.New("update refused by unit test"))
	onUpdateResult <- mockResult{err: conflictErr}

	// ensure controller does not attempt to update status of outdated resource
	select {
	case <-onUpdateStatusArgs:
		t.Fatal("UpdateStatus should not have be called after update conflict")
	default:
	}

	// update node2: remove occupied CIDR and add annotation
	updatedNode2 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
			Annotations: map[string]string{
				"test-annotation": "test-value",
			},
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool:   "default",
							Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16},
						},
					},
				},
			},
		},
	}

	// we now expect the controller to fetch the latest version of node2
	node2Get := <-onGetArgs
	assert.Equal(t, "node2", node2Get)
	onGetResult <- mockResult{node: updatedNode2}

	node2Update = <-onUpdateArgs
	assert.Equal(t, "node2", node2Update.newNode.Name)
	assert.Len(t, node2Update.newNode.Spec.IPAM.Pools.Allocated, 1)
	assert.Equal(t, "default", node2Update.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	assert.NotEqual(t, node1Update.newNode.Spec.IPAM.Pools.Allocated[0], node2Update.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	assert.Equal(t, "test-value", node2Update.newNode.Annotations["test-annotation"])
	onUpdateResult <- mockResult{node: node2Update.newNode}

	nh.Delete(node1Update.newNode)
	nh.Delete(node2Update.newNode)
}

func TestOrphanCIDRsAfterRestart(t *testing.T) {
	backend := NewPoolAllocator(hivetest.Logger(t))

	onUpdateArgs := make(chan mockArgs)

	onUpdateStatusArgs := make(chan mockArgs)
	onUpdateStatusResult := make(chan mockResult)

	nodeUpdater := &k8sNodeMock{
		OnUpdate: func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
			onUpdateArgs <- mockArgs{oldNode, newNode}
			return nil, nil
		},
		OnUpdateStatus: func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
			onUpdateStatusArgs <- mockArgs{oldNode, newNode}
			r := <-onUpdateStatusResult
			return r.node, r.err
		},
	}
	nh := NewNodeHandler(hivetest.Logger(t), backend, nodeUpdater)

	// wait 1ms instead of default 1s base duration in unit tests
	nh.controllerErrorRetryBaseDuration = 1 * time.Millisecond

	// upsert node with orphan CIDRs from previous operator run
	node := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool:   "test-pool",
							Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16},
						},
					},
					Allocated: []ipamTypes.IPAMPoolAllocation{
						{
							Pool: "test-pool",
							CIDRs: []ipamTypes.IPAMPodCIDR{
								"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24",
							},
						},
					},
				},
			},
		},
	}
	nh.Upsert(node)

	// CIDRs allocated from previous operator run should eventually be marked as orphans
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		backend.mutex.Lock()
		defer backend.mutex.Unlock()

		assert.Equal(c, map[string]poolToCIDRs{
			node.Name: {
				"test-pool": {
					v4: cidrSet{
						netip.MustParsePrefix("10.0.0.0/24"): {},
						netip.MustParsePrefix("10.0.1.0/24"): {},
						netip.MustParsePrefix("10.0.2.0/24"): {},
					},
					v6: cidrSet{},
				},
			},
		}, backend.orphans)
	}, 5*time.Second, 50*time.Millisecond)

	// Node should only be updated after Resync
	select {
	case <-onUpdateArgs:
		t.Fatal("Update should not have been called before Resync")
	default:
	}

	nh.Resync(t.Context(), time.Time{})

	// Node should not be updated, since all allocated CIDRs are orphan
	nodeUpdateStatus := <-onUpdateStatusArgs
	assert.Equal(t, "node", nodeUpdateStatus.newNode.Name)
	assert.Contains(t, nodeUpdateStatus.newNode.Status.IPAM.OperatorStatus.Error, "cannot allocate from non-existing pool: test-pool")
	onUpdateStatusResult <- mockResult{node: nodeUpdateStatus.newNode}

	select {
	case <-onUpdateArgs:
		t.Fatal("Update should not have been called after Resync")
	default:
	}

	// Node should not be updated, since we cannot allocate more CIDRs from non existent pools
	node2 := node.DeepCopy()
	node2.Spec.IPAM.Pools.Requested[0].Needed = ipamTypes.IPAMPoolDemand{IPv4Addrs: 24}
	nh.Upsert(node2)

	nodeUpdate2Status := <-onUpdateStatusArgs
	assert.Equal(t, "node", nodeUpdate2Status.newNode.Name)
	assert.Contains(t, nodeUpdate2Status.newNode.Status.IPAM.OperatorStatus.Error, "cannot allocate from non-existing pool: test-pool")
	onUpdateStatusResult <- mockResult{node: nodeUpdate2Status.newNode}

	select {
	case <-onUpdateArgs:
		t.Fatal("Update should not have been called after increasing requested IPs")
	default:
	}

	// Previous CIDRs should be unorphaned if test-pool is restored
	err := backend.UpsertPool("test-pool", []string{"10.0.0.0/16"}, 24, nil, 0)
	assert.NoError(t, err)

	assert.Empty(t, backend.orphans)
	assert.Equal(t, map[string]poolToCIDRs{
		node2.Name: {
			"test-pool": {
				v4: cidrSet{
					netip.MustParsePrefix("10.0.0.0/24"): {},
					netip.MustParsePrefix("10.0.1.0/24"): {},
					netip.MustParsePrefix("10.0.2.0/24"): {},
				},
				v6: cidrSet{},
			},
		},
	}, backend.nodes)
}

func TestOrphanCIDRsReleased(t *testing.T) {
	backend := NewPoolAllocator(hivetest.Logger(t))
	err := backend.UpsertPool("test-pool",
		[]string{"10.0.0.0/28", "10.0.0.16/28", "10.0.0.32/28", "10.0.0.48/28"}, 28,
		nil, 0)
	assert.NoError(t, err)

	onUpdateArgs := make(chan mockArgs)
	onUpdateResult := make(chan mockResult)
	nodeUpdater := &k8sNodeMock{
		OnUpdate: func(oldNode, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
			onUpdateArgs <- mockArgs{oldNode, newNode}
			r := <-onUpdateResult
			return r.node, r.err
		},
	}
	nh := NewNodeHandler(hivetest.Logger(t), backend, nodeUpdater)

	// wait 1ms instead of default 1s base duration in unit tests
	nh.controllerErrorRetryBaseDuration = 1 * time.Millisecond

	node := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool:   "test-pool",
							Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 48},
						},
					},
				},
			},
		},
	}
	nh.Upsert(node)

	nh.Resync(t.Context(), time.Time{})

	// CIDRs from test-pool should be allocated to node
	nodeUpdate := <-onUpdateArgs
	assert.Equal(t, node.Name, nodeUpdate.newNode.Name)
	assert.Len(t, nodeUpdate.newNode.Spec.IPAM.Pools.Allocated, 1)
	assert.Equal(t, "test-pool", nodeUpdate.newNode.Spec.IPAM.Pools.Allocated[0].Pool)
	assert.ElementsMatch(t, []ipamTypes.IPAMPodCIDR{
		"10.0.0.0/28", "10.0.0.16/28", "10.0.0.32/28", "10.0.0.48/28",
	}, nodeUpdate.newNode.Spec.IPAM.Pools.Allocated[0].CIDRs)
	onUpdateResult <- mockResult{node: nodeUpdate.newNode}

	assert.Equal(t, cidrSet{
		netip.MustParsePrefix("10.0.0.0/28"):  {},
		netip.MustParsePrefix("10.0.0.16/28"): {},
		netip.MustParsePrefix("10.0.0.32/28"): {},
		netip.MustParsePrefix("10.0.0.48/28"): {},
	}, backend.nodes[node.Name]["test-pool"].v4)
	assert.Empty(t, backend.orphans)

	// Shrink the pool and remove two CIDRs still in use by the node
	err = backend.UpsertPool("test-pool",
		[]string{"10.0.0.0/28", "10.0.0.16/28"}, 28,
		nil, 0)
	assert.NoError(t, err)

	assert.Equal(t, cidrSet{
		netip.MustParsePrefix("10.0.0.0/28"):  {},
		netip.MustParsePrefix("10.0.0.16/28"): {},
	}, backend.nodes[node.Name]["test-pool"].v4)
	assert.Equal(t, cidrSet{
		netip.MustParsePrefix("10.0.0.32/28"): {},
		netip.MustParsePrefix("10.0.0.48/28"): {},
	}, backend.orphans[node.Name]["test-pool"].v4)

	// when orphan CIDRs are not claimed by the node anymore, they should eventually be released
	node.Spec.IPAM.Pools.Requested = []ipamTypes.IPAMPoolRequest{{
		Pool:   "test-pool",
		Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 24},
	}}
	node.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{{
		Pool:  "test-pool",
		CIDRs: []ipamTypes.IPAMPodCIDR{"10.0.0.0/28", "10.0.0.16/28"},
	}}
	nh.Upsert(node)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		backend.mutex.Lock()
		defer backend.mutex.Unlock()

		assert.Equal(c, cidrSet{
			netip.MustParsePrefix("10.0.0.0/28"):  {},
			netip.MustParsePrefix("10.0.0.16/28"): {},
		}, backend.nodes[node.Name]["test-pool"].v4)
		assert.Empty(c, backend.orphans[node.Name]["test-pool"].v4)
	}, 5*time.Second, 50*time.Millisecond)

	select {
	case <-onUpdateArgs:
		t.Fatal("Update should not have been called after releasing orphan CIDRs")
	default:
	}
}
