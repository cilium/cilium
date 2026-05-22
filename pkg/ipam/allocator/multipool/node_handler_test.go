// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTesting "k8s.io/client-go/testing"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumFake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
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
	err := backend.addPool("default", []string{"10.0.0.0/8"}, 24, nil, 0)
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

func TestNodeHandlerRetries(t *testing.T) {
	nodeUpdater := func(t *testing.T, clientset *ciliumFake.Clientset) *k8sNodeMock {
		return &k8sNodeMock{
			OnUpdate: func(_, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
				return clientset.CiliumV2().CiliumNodes().Update(t.Context(), newNode, metav1.UpdateOptions{})
			},
			OnUpdateStatus: func(_, newNode *v2.CiliumNode) (*v2.CiliumNode, error) {
				return clientset.CiliumV2().CiliumNodes().UpdateStatus(t.Context(), newNode, metav1.UpdateOptions{})
			},
			OnGet: func(node string) (*v2.CiliumNode, error) {
				return clientset.CiliumV2().CiliumNodes().Get(t.Context(), node, metav1.GetOptions{})
			},
			OnCreate: func(node *v2.CiliumNode) (*v2.CiliumNode, error) {
				return clientset.CiliumV2().CiliumNodes().Create(t.Context(), node, metav1.CreateOptions{})
			},
		}
	}

	t.Run("get and update", func(t *testing.T) {
		backend := NewPoolAllocator(hivetest.Logger(t))
		assert.NoError(t, backend.UpsertPool("default", []string{"10.0.0.0/8"}, 24, nil, 0))

		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-status",
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
			Status: v2.NodeStatus{
				IPAM: ipamTypes.IPAMStatus{
					OperatorStatus: ipamTypes.OperatorStatus{Error: "stale allocation error"},
				},
			},
		}

		clientset := ciliumFake.NewSimpleClientset(node.DeepCopy())

		var (
			gets    atomic.Int32
			updates atomic.Int32
		)
		clientset.PrependReactor("get", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
			gets.Add(1)
			if gets.Load() == 1 {
				return true, nil, errors.New("transient get failure")
			}
			return false, nil, nil
		})
		clientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "" {
				return false, nil, nil
			}

			updates.Add(1)
			if updates.Load() == 1 {
				return true, nil, k8sErrors.NewConflict(
					schema.GroupResource{
						Group:    v2.CustomResourceDefinitionGroup,
						Resource: v2.CNPluralName,
					},
					node.Name,
					errors.New("update refused by unit test"),
				)
			}
			return false, nil, nil
		})

		nh := NewNodeHandler(hivetest.Logger(t), backend, nodeUpdater(t, clientset))
		nh.controllerErrorRetryBaseDuration = time.Millisecond

		nh.Upsert(node)
		nh.Resync(t.Context(), time.Time{})

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			// wait for controller to retry after:
			// - transient get failure
			// - update conflict
			assert.GreaterOrEqual(c, gets.Load(), int32(2))
			assert.GreaterOrEqual(c, updates.Load(), int32(2))
		}, 5*time.Second, 10*time.Millisecond)

		updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, updatedNode.Spec.IPAM.Pools.Allocated, 1)
		require.Equal(t, "default", updatedNode.Spec.IPAM.Pools.Allocated[0].Pool)
	})

	t.Run("updatestatus", func(t *testing.T) {
		backend := NewPoolAllocator(hivetest.Logger(t))
		assert.NoError(t, backend.UpsertPool("default", []string{"10.0.0.0/8"}, 24, nil, 0))

		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: "node-status",
			},
			Spec: v2.NodeSpec{
				IPAM: ipamTypes.IPAMSpec{
					Pools: ipamTypes.IPAMPoolSpec{
						Allocated: []ipamTypes.IPAMPoolAllocation{
							{
								Pool:  "default",
								CIDRs: []ipamTypes.IPAMPodCIDR{"10.0.0.0/24"},
							},
						},
						Requested: []ipamTypes.IPAMPoolRequest{
							{
								Pool:   "default",
								Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 16},
							},
						},
					},
				},
			},
			Status: v2.NodeStatus{
				IPAM: ipamTypes.IPAMStatus{
					OperatorStatus: ipamTypes.OperatorStatus{Error: "stale allocation error"},
				},
			},
		}

		clientset := ciliumFake.NewSimpleClientset(node.DeepCopy())

		var updateStatuses atomic.Int32
		clientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "status" {
				return false, nil, nil
			}

			if updateStatuses.Add(1) == 1 {
				return true, nil, k8sErrors.NewConflict(
					schema.GroupResource{
						Group:    v2.CustomResourceDefinitionGroup,
						Resource: v2.CNPluralName,
					},
					node.Name,
					errors.New("update refused by unit test"),
				)
			}
			return false, nil, nil
		})

		nh := NewNodeHandler(hivetest.Logger(t), backend, nodeUpdater(t, clientset))
		nh.controllerErrorRetryBaseDuration = time.Millisecond

		nh.Upsert(node)
		nh.Resync(t.Context(), time.Time{})

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			// wait for controller to retry after update conflict on status update
			assert.GreaterOrEqual(c, updateStatuses.Load(), int32(2))
		}, 5*time.Second, 10*time.Millisecond)

		updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
		assert.NoError(t, err)
		assert.Empty(t, updatedNode.Status.IPAM.OperatorStatus.Error)
	})
}
