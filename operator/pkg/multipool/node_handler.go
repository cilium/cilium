// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/allocator"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

type NodeHandler struct {
	logger *slog.Logger
	mutex  lock.Mutex

	poolManager       *PoolAllocator
	cnClient          cilium_v2.CiliumNodeInterface
	poolsFromResource v2.PoolsFromResourceFunc

	name string

	nodesPendingAllocation map[string]*v2.CiliumNode
	restoreFinished        bool

	controllerManager                *controller.Manager
	controllerGroup                  controller.Group
	controllerErrorRetryBaseDuration time.Duration // only set in unit tests
}

var _ allocator.NodeEventHandler = (*NodeHandler)(nil)

func NewNodeHandler(
	name string,
	logger *slog.Logger,
	manager *PoolAllocator,
	cnClient cilium_v2.CiliumNodeInterface,
	poolsFromResource v2.PoolsFromResourceFunc,
) *NodeHandler {
	return &NodeHandler{
		logger:                 logger,
		poolManager:            manager,
		cnClient:               cnClient,
		poolsFromResource:      poolsFromResource,
		name:                   name,
		nodesPendingAllocation: map[string]*v2.CiliumNode{},
		controllerManager:      controller.NewManager(),
		controllerGroup:        controller.NewGroup(name),
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
		n.logger.Warn(
			"Errors while release node and its CIDRs",
			logfields.Error, err,
			logfields.NodeName, resource.Name,
		)
	}

	delete(n.nodesPendingAllocation, resource.Name)

	// Make sure any pending update controller is stopped
	n.controllerManager.RemoveController(controllerName(n.name, resource.Name))
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

func (n *NodeHandler) Stop() {
	n.controllerManager.RemoveAllAndWait()
}

func (n *NodeHandler) upsertLocked(resource *v2.CiliumNode) {
	if !n.restoreFinished {
		n.nodesPendingAllocation[resource.Name] = resource
		pools := n.poolsFromResource(resource)
		_ = n.poolManager.AllocateToNode(resource.Name, pools)
		return
	}

	n.createUpsertController(resource)
}

func (n *NodeHandler) createUpsertController(resource *v2.CiliumNode) {
	// This controller serves two purposes:
	// 1. It will retry allocations upon failure, e.g. if a pool does not exist yet.
	// 2. Will try to synchronize the allocator's state with the CiliumNode CRD in k8s.
	refetchNode := false
	n.controllerManager.UpdateController(controllerName(n.name, resource.Name), controller.ControllerParams{
		Group:                  controller.NewGroup(n.name),
		ErrorRetryBaseDuration: n.controllerErrorRetryBaseDuration,
		DoFunc: func(ctx context.Context) error {
			// errorMessage is written to the resource status
			errorMessage := ""
			var controllerErr error

			// If a previous run of the controller failed due to a conflict,
			// we need to re-fetch the node to make sure we have the latest version.
			if refetchNode {
				resource, controllerErr = n.cnClient.Get(ctx, resource.Name, metav1.GetOptions{})
				if controllerErr != nil {
					return controllerErr
				}
				refetchNode = false
			}

			pools := n.poolsFromResource(resource)
			err := n.poolManager.AllocateToNode(resource.Name, pools)
			if err != nil {
				n.logger.Warn(
					"Failed to allocate CIDRs to node",
					logfields.Error, err,
					logfields.NodeName, resource.Name,
				)
				errorMessage = fmt.Sprintf("%s allocation failed: %s", n.name, err.Error())
				controllerErr = err
			}

			newResource := resource.DeepCopy()
			newResource.Status.IPAM.OperatorStatus.Error = errorMessage

			newPools := n.poolsFromResource(newResource)
			newPools.Allocated = n.poolManager.AllocatedPools(newResource.Name)

			if !newPools.DeepEqual(pools) {
				_, err = n.cnClient.Update(ctx, newResource, metav1.UpdateOptions{})
				if err != nil {
					controllerErr = errors.Join(controllerErr, fmt.Errorf("failed to update spec: %w", err))
					if k8sErrors.IsConflict(err) {
						refetchNode = true
					}
				}
			}

			if !newResource.Status.IPAM.OperatorStatus.DeepEqual(&resource.Status.IPAM.OperatorStatus) && !refetchNode {
				_, err = n.cnClient.UpdateStatus(ctx, newResource, metav1.UpdateOptions{})
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

func controllerName(prefix string, nodeName string) string {
	return prefix + nodeName
}
