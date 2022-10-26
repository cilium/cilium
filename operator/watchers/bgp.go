// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	"github.com/cilium/cilium/pkg/bgp/manager"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// StartBGPBetaLBIPAllocator starts the service watcher if it hasn't already and looks
// for service of type LoadBalancer. Once it finds a service of that type, it
// will try to allocate an external IP (LoadBalancerIP) for it.
func StartBGPBetaLBIPAllocator(ctx context.Context, services resource.Resource[*slim_corev1.Service]) {
	go func() {
		store, err := services.Store(ctx)
		if err != nil {
			log.WithError(err).Fatal("Failed to retrieve service store")
		}

		m, err := manager.New(ctx, store.CacheStore())
		if err != nil {
			log.WithError(err).Fatal("Error creating BGP manager")
		}

		services.Observe(
			ctx,
			func(ev resource.Event[*slim_corev1.Service]) {
				ev.Handle(
					func() error {
						m.MarkSynced()
						return nil
					},
					func(_ resource.Key, svc *slim_corev1.Service) error {
						m.OnUpdateService(nil, svc)
						return nil
					},
					func(_ resource.Key, svc *slim_corev1.Service) error {
						m.OnDeleteService(svc)
						return nil
					},
				)
			},
			func(error) { /* only completes when stopping */ },
		)
	}()
}
