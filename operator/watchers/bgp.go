// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"os"

	"github.com/cilium/cilium/pkg/bgp/manager"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// StartBGPBetaLBIPAllocator starts the service watcher if it hasn't already and looks
// for service of type LoadBalancer. Once it finds a service of that type, it
// will try to allocate an external IP (LoadBalancerIP) for it.
func StartBGPBetaLBIPAllocator(ctx context.Context, clientset client.Clientset, services resource.Resource[*slim_corev1.Service]) {
	go func() {
		store, err := services.Store(ctx)
		if err != nil {
			log.Error("Failed to retrieve service store", logfields.Error, err)
			os.Exit(1)
		}

		m, err := manager.New(ctx, clientset, store.CacheStore())
		if err != nil {
			log.Error("Error creating BGP manager", logfields.Error, err)
			os.Exit(1)
		}

		for ev := range services.Events(ctx) {
			switch ev.Kind {
			case resource.Sync:
				m.MarkSynced()
			case resource.Upsert:
				m.OnUpdateService(nil, ev.Object)
			case resource.Delete:
				m.OnDeleteService(ev.Object)
			}
			ev.Done(nil)
		}
	}()
}
