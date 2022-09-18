// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	"github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// StartCECController starts the service watcher if it hasn't already and looks
// for service of type with envoy enabled LB annotation. Once such service is
// found, it will try to create one CEC associated with the service.
func StartCECController(ctx context.Context, clientset k8sClient.Clientset, services resource.Resource[*slim_corev1.Service], ports []string) {
	go func() {
		store, err := services.Store(ctx)
		if err != nil {
			log.WithError(err).Fatal("Failed to retrieve service store")
		}

		m, err := ciliumenvoyconfig.New(clientset, store.CacheStore(), ports )
		if err != nil {
			log.WithError(err).Fatal("Error creating CiliumEnvoyConfiguration manager")
		}
		go m.Run(ctx)

		services.Observe(
			ctx,
			func(ev resource.Event[*slim_corev1.Service]) {
				ev.Handle(
					func() error {
						m.MarkSynced()
						return nil
					},
					func(_ resource.Key, svc *slim_corev1.Service) error {
						return m.OnUpdateService(nil, svc)
					},
					func(_ resource.Key, svc *slim_corev1.Service) error {
						return m.OnDeleteService(svc)
					},
				)
			},
			func(error) { /* only completes when stopping */ },
		)
	}()
}
