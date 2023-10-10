// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package allocator

import (
	"context"

	"github.com/cilium/cilium/pkg/ipam"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/time"
)

// AllocatorProvider defines the functions of IPAM provider front-end
// these are implemented by e.g. pkg/ipam/allocator/{aws,azure}.
type AllocatorProvider interface {
	Init(ctx context.Context) error
	Start(ctx context.Context, getterUpdater ipam.CiliumNodeGetterUpdater) (NodeEventHandler, error)
}

// NodeEventHandler should implement the behavior to handle CiliumNode
type NodeEventHandler interface {
	Upsert(resource *v2.CiliumNode)
	Delete(resource *v2.CiliumNode)
	Resync(context.Context, time.Time)
}
