// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// PooledAllocatorProvider defines the functions of IPAM provider front-end which additionally allow
// definition of IP pools at runtime.
// This is implemented by e.g. pkg/ipam/allocator/multipool
type PooledAllocatorProvider interface {
	UpsertPool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error
	DeletePool(ctx context.Context, pool *cilium_v2alpha1.CiliumPodIPPool) error
}

func StartIPPoolAllocator(
	ctx context.Context,
	clientset client.Clientset,
	allocator PooledAllocatorProvider,
	ipPools resource.Resource[*cilium_v2alpha1.CiliumPodIPPool],
) {
	log.Info("Starting CiliumPodIPPool allocator watcher")

	synced := make(chan struct{})

	go func() {
		for ev := range ipPools.Events(ctx) {
			var err error
			var action string

			switch ev.Kind {
			case resource.Sync:
				close(synced)
			case resource.Upsert:
				err = allocator.UpsertPool(ctx, ev.Object)
				action = "upsert"
			case resource.Delete:
				err = allocator.DeletePool(ctx, ev.Object)
				action = "delete"
			}
			ev.Done(err)
			if err != nil {
				log.WithError(err).Errorf("failed to %s pool %q", action, ev.Key)
			}
		}
	}()

	// Block until all pools are restored, so callers can safely start node allocation
	// right after return.
	<-synced
	log.Info("All CiliumPodIPPool resources synchronized")
}
