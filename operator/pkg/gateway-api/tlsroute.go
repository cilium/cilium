// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// tlsRouteReconciler reconciles a TLSRoute object
type tlsRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	logger *slog.Logger
}

func newTLSRouteReconciler(mgr ctrl.Manager, logger *slog.Logger) *tlsRouteReconciler {
	return &tlsRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		logger: logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *tlsRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TLSRoute{}, backendServiceIndex,
		func(rawObj client.Object) []string {
			route, ok := rawObj.(*gatewayv1alpha2.TLSRoute)
			if !ok {
				return nil
			}
			var backendServices []string
			for _, rule := range route.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
					backendServiceName, err := helpers.GetBackendServiceName(r.Client, namespace, backend.BackendObjectReference)
					if err != nil {
						r.logger.Error("Failed to get backend service name",
							logfields.Controller, "tlsRoute",
							logfields.Resource, client.ObjectKeyFromObject(rawObj), logfields.Error, err)
						continue
					}
					backendServices = append(backendServices,
						types.NamespacedName{
							Namespace: helpers.NamespaceDerefOr(backend.Namespace, route.Namespace),
							Name:      backendServiceName,
						}.String(),
					)
				}
			}
			return backendServices
		},
	); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TLSRoute{}, backendServiceImportIndex,
		func(rawObj client.Object) []string {
			hr, ok := rawObj.(*gatewayv1alpha2.TLSRoute)
			if !ok {
				return nil
			}
			var backendServiceImports []string
			for _, rule := range hr.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if !helpers.IsServiceImport(backend.BackendObjectReference) {
						continue
					}
					backendServiceImports = append(backendServiceImports,
						types.NamespacedName{
							Namespace: helpers.NamespaceDerefOr(backend.Namespace, hr.Namespace),
							Name:      string(backend.Name),
						}.String(),
					)
				}
			}
			return backendServiceImports
		},
	); err != nil {
		return err
	}

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TLSRoute{}, gatewayIndex,
		func(rawObj client.Object) []string {
			hr := rawObj.(*gatewayv1alpha2.TLSRoute)
			var gateways []string
			for _, parent := range hr.Spec.ParentRefs {
				if !helpers.IsGateway(parent) {
					continue
				}
				gateways = append(gateways,
					types.NamespacedName{
						Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
						Name:      string(parent.Name),
					}.String(),
				)
			}
			return gateways
		},
	); err != nil {
		return err
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		// Watch for changes to TLSRoute
		For(&gatewayv1alpha2.TLSRoute{},
			builder.WithPredicates(predicate.NewPredicateFuncs(r.hasMatchingGatewayParent()))).
		// Watch for changes to Backend services
		Watches(&corev1.Service{}, r.enqueueRequestForBackendService()).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1beta1.ReferenceGrant{}, r.enqueueRequestForReferenceGrant()).
		// Watch for changes to Gateways and enqueue TLSRoutes that reference them
		Watches(&gatewayv1.Gateway{}, r.enqueueRequestForGateway(),
			builder.WithPredicates(
				predicate.NewPredicateFuncs(hasMatchingController(context.Background(), mgr.GetClient(), controllerName, r.logger)),
			))

	if helpers.HasServiceImportSupport(r.Client.Scheme()) {
		// Watch for changes to Backend Service Imports
		builder = builder.Watches(&mcsapiv1alpha1.ServiceImport{}, r.enqueueRequestForBackendServiceImport())
	}

	return builder.Complete(r)
}

// enqueueRequestForBackendService makes sure that TLS Routes are reconciled
// if the backend services are updated.
func (r *tlsRouteReconciler) enqueueRequestForBackendService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(backendServiceIndex))
}

// enqueueRequestForBackendServiceImport makes sure that TLS Routes are reconciled
// if the backend Service Imports are updated.
func (r *tlsRouteReconciler) enqueueRequestForBackendServiceImport() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(backendServiceImportIndex))
}

// enqueueRequestForReferenceGrant makes sure that all TLS Routes are reconciled
// if a ReferenceGrant changes
func (r *tlsRouteReconciler) enqueueRequestForReferenceGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueAll())
}

func (r *tlsRouteReconciler) enqueueRequestForGateway() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayIndex))
}

func (r *tlsRouteReconciler) enqueueFromIndex(index string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, tlsRoute, logfields.Resource, client.ObjectKeyFromObject(o))
		rList := &gatewayv1alpha2.TLSRouteList{}

		if err := r.Client.List(context.Background(), rList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.Error("Failed to get related TLSRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(rList.Items))
		for _, item := range rList.Items {
			route := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: route,
			})
			scopedLog.Info("Enqueued TLSRoute for resource", tlsRoute, route)
		}
		return requests
	}
}

func (r *tlsRouteReconciler) enqueueAll() handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, tlsRoute, logfields.Resource, client.ObjectKeyFromObject(o))

		trList := &gatewayv1alpha2.TLSRouteList{}

		if err := r.Client.List(ctx, trList, &client.ListOptions{}); err != nil {
			scopedLog.Error("Failed to get TLSRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(trList.Items))
		for _, item := range trList.Items {
			route := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: route,
			})
			scopedLog.Info("Enqueued TLSRoute for resource", tlsRoute, route)
		}
		return requests
	}
}

func (r *tlsRouteReconciler) hasMatchingGatewayParent() func(object client.Object) bool {
	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)
	return func(obj client.Object) bool {
		tr, ok := obj.(*gatewayv1alpha2.TLSRoute)
		if !ok {
			return false
		}

		for _, parent := range tr.Spec.ParentRefs {
			if !helpers.IsGateway(parent) {
				continue
			}
			gw := &gatewayv1.Gateway{}
			if err := r.Client.Get(context.Background(), types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, tr.Namespace),
				Name:      string(parent.Name),
			}, gw); err != nil {
				continue
			}
			if hasMatchingControllerFn(gw) {
				return true
			}
		}

		return false
	}
}
