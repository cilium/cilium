// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gwModel "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueFrontendsForBackendEndpointSlice returns an event handler that, when
// passed a backend EndpointSlice, returns reconcile.Requests for all managed
// frontend EndpointSlices whose BackendServiceAnnotation matches the backend
// Service the slice belongs to (via the kubernetes.io/service-name label).
func EnqueueFrontendsForBackendEndpointSlice(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		eps, ok := o.(*discoveryv1.EndpointSlice)
		if !ok {
			return nil
		}
		svcName := eps.Labels[gwModel.EndpointSliceServiceNameLabel]
		if svcName == "" {
			return nil
		}
		return frontendsMatchingBackend(ctx, c, logger, eps.Namespace, svcName)
	})
}

// EnqueueFrontendsForBackendService returns an event handler that, when passed
// a Service, returns reconcile.Requests for all managed frontend EndpointSlices
// whose BackendServiceAnnotation references that Service.
func EnqueueFrontendsForBackendService(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		svc, ok := o.(*corev1.Service)
		if !ok {
			return nil
		}
		return frontendsMatchingBackend(ctx, c, logger, svc.Namespace, svc.Name)
	})
}

func frontendsMatchingBackend(ctx context.Context, c client.Client, logger *slog.Logger, ns, name string) []reconcile.Request {
	wantBackend := ns + "/" + name

	list := &discoveryv1.EndpointSliceList{}
	if err := c.List(ctx, list, client.MatchingLabels{
		gwModel.EndpointSliceManagedByLabel: gwModel.EndpointSliceManagedByValue,
	}); err != nil {
		logger.WarnContext(ctx, "Failed to list managed EndpointSlices",
			logfields.Error, err)
		return nil
	}

	var reqs []reconcile.Request
	for i := range list.Items {
		fe := list.Items[i]
		if fe.Annotations[gwModel.BackendServiceAnnotation] == wantBackend {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: fe.Namespace, Name: fe.Name},
			})
		}
	}
	return reqs
}
