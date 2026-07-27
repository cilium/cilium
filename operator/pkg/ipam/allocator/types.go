// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"

	"github.com/cilium/hive/job"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/time"
)

// NodeEventHandler should implement the behavior to handle CiliumNode
type NodeEventHandler interface {
	Upsert(resource *v2.CiliumNode)
	Delete(resource *v2.CiliumNode)
	Resync(context.Context, time.Time)
	Stop()
}

// CiliumNodeGetterUpdater defines the interface used to interact with the k8s
// apiserver to retrieve and update the CiliumNode custom resource
type CiliumNodeGetterUpdater interface {
	Create(node *v2.CiliumNode) (*v2.CiliumNode, error)
	Update(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	UpdateStatus(origResource, newResource *v2.CiliumNode) (*v2.CiliumNode, error)
	Get(name string) (*v2.CiliumNode, error)
}

// NodeEventHandlerFactory is a function type that returns a NodeEventHandler, used to decouple
// the allocator logic from the specific implementation of the CiliumNode event handling.
type NodeEventHandlerFactory func(ctx context.Context) (NodeEventHandler, error)

// NodeWatcherJobFactory is a function type that returns a Job responsible for watching CiliumNode resources
// and triggering the appropriate events in the allocator.
type NodeWatcherJobFactory func(nmFactory NodeEventHandlerFactory) job.Job
