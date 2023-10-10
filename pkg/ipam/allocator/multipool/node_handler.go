// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"errors"
	"fmt"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type NodeHandler struct {
	mutex lock.Mutex

	poolManager *PoolAllocator
	nodeUpdater ipam.CiliumNodeGetterUpdater

	nodesPendingAllocation map[string]*v2.CiliumNode
	restoreFinished        bool

	controllerManager                *controller.Manager
	controllerErrorRetryBaseDuration time.Duration // only set in unit tests
}

var ipamMultipoolSyncControllerGroup = controller.NewGroup("ipam-multi-pool-sync")

var _ allocator.NodeEventHandler = (*NodeHandler)(nil)

func NewNodeHandler(manager *PoolAllocator, nodeUpdater ipam.CiliumNodeGetterUpdater) *NodeHandler {
	return &NodeHandler{
		poolManager:            manager,
		nodeUpdater:            nodeUpdater,
		nodesPendingAllocation: map[string]*v2.CiliumNode{},
		controllerManager:      controller.NewManager(),
	}
}

func (n *NodeHandler) Upsert(resource *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.upsertLocked(resource)
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

	delete(n.nodesPendingAllocation, resource.Name)

	// Make sure any pending update controller is stopped
	n.controllerManager.RemoveController(controllerName(resource.Name))
}

func (n *NodeHandler) Resync(context.Context, time.Time) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.poolManager.RestoreFinished()
	for _, cn := range n.nodesPendingAllocation {
		delete(n.nodesPendingAllocation, cn.Name)
		n.createUpsertController(cn)
	}
	n.restoreFinished = true
	n.nodesPendingAllocation = nil
}

func (n *NodeHandler) upsertLocked(resource *v2.CiliumNode) {
	if !n.restoreFinished {
		n.nodesPendingAllocation[resource.Name] = resource
		_ = n.poolManager.AllocateToNode(resource)
		return
	}

	n.createUpsertController(resource)
}

func (n *NodeHandler) createUpsertController(resource *v2.CiliumNode) {
	// This controller serves two purposes:
	// 1. It will retry allocations upon failure, e.g. if a pool does not exist yet.
	// 2. Will try to synchronize the allocator's state with the CiliumNode CRD in k8s.
	refetchNode := false
	n.controllerManager.UpdateController(controllerName(resource.Name), controller.ControllerParams{
		Group:                  ipamMultipoolSyncControllerGroup,
		ErrorRetryBaseDuration: n.controllerErrorRetryBaseDuration,
		DoFunc: func(ctx context.Context) error {
			// errorMessage is written to the resource status
			errorMessage := ""
			var controllerErr error

			// If a previous run of the controller failed due to a conflict,
			// we need to re-fetch the node to make sure we have the latest version.
			if refetchNode {
				resource, controllerErr = n.nodeUpdater.Get(resource.Name)
				if controllerErr != nil {
					return controllerErr
				}
				refetchNode = false
			}

			err := n.poolManager.AllocateToNode(resource)
			if err != nil {
				log.WithField(logfields.NodeName, resource.Name).WithError(err).
					Warning("Failed to allocate PodCIDRs to node")
				errorMessage = err.Error()
				controllerErr = err
			}

			newResource := resource.DeepCopy()
			newResource.Status.IPAM.OperatorStatus.Error = errorMessage

			newResource.Spec.IPAM.Pools.Allocated = n.poolManager.AllocatedPools(newResource.Name)

			if !newResource.Spec.IPAM.Pools.DeepEqual(&resource.Spec.IPAM.Pools) {
				_, err = n.nodeUpdater.Update(resource, newResource)
				if err != nil {
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update spec: %w", err))
					if k8sErrors.IsConflict(err) {
						refetchNode = true
					}
				}
			}

			if !newResource.Status.IPAM.OperatorStatus.DeepEqual(&resource.Status.IPAM.OperatorStatus) && !refetchNode {
				_, err = n.nodeUpdater.UpdateStatus(resource, newResource)
				if err != nil {
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update status: %w", err))
					if k8sErrors.IsConflict(err) {
						refetchNode = true
					}
				}
			}

			return controllerErr
		},
	})
}

func controllerName(nodeName string) string {
	return "ipam-multi-pool-sync-" + nodeName
}
