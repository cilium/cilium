// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EnqueueRequestForOwningInferencePool returns an event handler that, when passed a InferencePool, returns reconcile.Requests
// for all Cilium-relevant Gateways associated with that InferencePool.
func EnqueueRequestForOwningInferencePool(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		// get all the httproutes that refers to the inferencepool
		inferencePool, ok := a.(*gateway_inf_ext.InferencePool)
		if !ok {
			return nil
		}
		return gatewayRequestForInferencePool(ctx, c, inferencePool, logger, controllerName)
	})
}

// EnqueueRequestForOwningEndpointSlice returns an event handler that, when passed an
// EndPointSlice, returns reconcile.Requests for all the
// Cilium-relevant Gateways
func EnqueueRequestForOwningEndpointSlice(c client.Client, logger *slog.Logger, controllerName string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, a client.Object) []reconcile.Request {
		// get the endpointslices for a shadow service created from an inferencePool
		eps, ok := a.(*discoveryv1.EndpointSlice)
		if !ok {
			return nil
		}
		svcName := eps.Labels[discoveryv1.LabelServiceName]
		if svcName == "" {
			return nil
		}

		svc := &corev1.Service{}
		if err := c.Get(ctx, types.NamespacedName{
			Name:      svcName,
			Namespace: eps.Namespace,
		}, svc); err != nil {
			return nil
		}

		for _, ref := range svc.OwnerReferences {
			if ref.Kind == "InferencePool" {
				infPool := &gateway_inf_ext.InferencePool{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ref.Name,
						Namespace: eps.Namespace,
					},
				}
				return gatewayRequestForInferencePool(ctx, c, infPool, logger, controllerName)
			}
		}
		return nil
	})
}

// gets the HTTPRoutes and keeps the one that references InferencePools
// and resolves the matching route's parentRef to the relevant
// Cilium-gateway
func gatewayRequestForInferencePool(ctx context.Context, c client.Client, inferencePool *gateway_inf_ext.InferencePool, logger *slog.Logger, controllerName string) []reconcile.Request {
	httpRouteList := &gatewayv1.HTTPRouteList{}
	if err := c.List(ctx, httpRouteList); err != nil {
		logger.WarnContext(ctx, "unabel to list httproutes", logfields.Error, err)
		return nil
	}

	var reqs []reconcile.Request
	for _, hr := range httpRouteList.Items {
		reqs = append(reqs, getGatewayReconcileRequestsForRoute(ctx, c, inferencePool, hr.Spec.CommonRouteSpec, logger, controllerName)...)
	}
	return reqs
}

// compare the kind from gateway inference and gateway backendref
func backendRefMatchesInferencePool(ref gatewayv1.HTTPBackendRef, routeNs string, infPool *gateway_inf_ext.InferencePool) bool {
	if !helpers.IsInferencePool(ref.BackendObjectReference) {
		return false
	}
	if string(ref.Name) != infPool.Name {
		return false
	}
	ns := routeNs
	if ref.Namespace != nil {
		ns = string(*ref.Namespace)
	}
	return ns == infPool.Namespace
}
