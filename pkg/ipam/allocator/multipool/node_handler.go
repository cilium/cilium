// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"

	"github.com/cilium/cilium/pkg/logging/logfields"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
)

type NodeHandler struct {
	mutex lock.Mutex

	poolManager *PoolAllocator
	nodeUpdater ipam.CiliumNodeGetterUpdater

	nodesPendingAllocation map[string]*v2.CiliumNode
	nodesPendingK8sUpdate  map[string]*v2.CiliumNode

	controllerManager *controller.Manager
}

var _ allocator.NodeEventHandler = (*NodeHandler)(nil)

func NewNodeHandler(manager *PoolAllocator, nodeUpdater ipam.CiliumNodeGetterUpdater) *NodeHandler {
	return &NodeHandler{
		poolManager:            manager,
		nodeUpdater:            nodeUpdater,
		nodesPendingAllocation: map[string]*v2.CiliumNode{},
		nodesPendingK8sUpdate:  map[string]*v2.CiliumNode{},
		controllerManager:      controller.NewManager(),
	}
}

func (n *NodeHandler) Create(resource *v2.CiliumNode) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.upsertLocked(resource)
}

func (n *NodeHandler) Update(resource *v2.CiliumNode) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.upsertLocked(resource)
}

func (n *NodeHandler) Delete(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	err := n.poolManager.ReleaseNode(resource.Name)
	if err != nil {
		log.WithField(logfields.NodeName, resource.Name).
			WithError(err).
			Warning("Errors while release node and its CIDRs")
	}

	// Make sure any pending update controller is stopped
	n.controllerManager.RemoveController(controllerName(resource.Name))
}

func (n *NodeHandler) Resync(ctx context.Context, time time.Time) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.poolManager.RestoreFinished()
	for _, cn := range n.nodesPendingAllocation {
		delete(n.nodesPendingAllocation, cn.Name)
		n.upsertLocked(cn)
	}
}

func (n *NodeHandler) upsertLocked(resource *v2.CiliumNode) bool {
	err := n.poolManager.AllocateToNode(resource)
	if err != nil {
		if errors.Is(err, ErrAllocatorNotReady) {
			n.nodesPendingAllocation[resource.Name] = resource
			return false // try again later
		} else {
			log.WithField(logfields.NodeName, resource.Name).WithError(err).
				Warning("Failed to allocate PodCIDRs to node")
		}
	}

	// refreshNode is set to true if the node needs to be refreshed before
	// performing the update
	refreshNode := false
	// errorMessage is written to the resource status
	errorMessage := ""
	if err != nil {
		errorMessage = err.Error()
	}

	n.controllerManager.UpdateController(controllerName(resource.Name), controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			if refreshNode {
				resource, err = n.nodeUpdater.Get(resource.Name)
				if err != nil {
					return fmt.Errorf("failed to refresh node: %w", err)
				}
			}
			newResource := resource.DeepCopy()
			newResource.Status.IPAM.OperatorStatus.Error = errorMessage

			n.mutex.Lock()
			newResource.Spec.IPAM.Pools.Allocated = n.poolManager.AllocatedPools(newResource.Name)
			n.mutex.Unlock()

			var controllerErr error
			if !newResource.Spec.IPAM.Pools.DeepEqual(&resource.Spec.IPAM.Pools) {
				_, err = n.nodeUpdater.Update(resource, newResource)
				if err != nil {
					refreshNode = true
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update spec: %w", err))
				}
			}

			if !newResource.Status.IPAM.OperatorStatus.DeepEqual(&resource.Status.IPAM.OperatorStatus) {
				_, err = n.nodeUpdater.UpdateStatus(resource, newResource)
				if err != nil {
					refreshNode = true
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update status: %w", err))
				}
			}

			return controllerErr
		},
	})
	return true
}

func controllerName(nodeName string) string {
	return "ipam-multi-pool-sync-" + nodeName
}
