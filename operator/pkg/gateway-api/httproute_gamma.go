// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"
	"strings"

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
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// gammaHttpRouteReconciler reconciles a HTTPRoute object
type gammaHttpRouteReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator
	logger     *slog.Logger
}

func newGammaHttpRouteReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger) *gammaHttpRouteReconciler {
	return &gammaHttpRouteReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		translator: translator,
		logger:     logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *gammaHttpRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, gammaBackendServiceIndex,
		func(rawObj client.Object) []string {
			route, ok := rawObj.(*gatewayv1.HTTPRoute)
			if !ok {
				return nil
			}

			if !r.hasGammaParent()(route) {
				return nil
			}
			var backendServices []string
			for _, rule := range route.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
					backendServiceName, err := helpers.GetBackendServiceName(r.Client, namespace, backend.BackendObjectReference)
					if err != nil {
						r.logger.Error("Failed to get backend service name",
							logfields.Controller, "gammaHttpRoute",
							logfields.Resource, client.ObjectKeyFromObject(rawObj),
							logfields.Error, err)
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

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, gammaListenerServiceIndex,
		func(rawObj client.Object) []string {
			hr, ok := rawObj.(*gatewayv1.HTTPRoute)
			if !ok {
				return nil
			}

			if !r.hasGammaParent()(hr) {
				return nil
			}

			var services []string
			for _, parent := range hr.Spec.ParentRefs {
				if !helpers.IsGammaService(parent) {
					continue
				}
				services = append(services,
					types.NamespacedName{
						Namespace: helpers.NamespaceDerefOr(parent.Namespace, hr.Namespace),
						Name:      string(parent.Name),
					}.String(),
				)
			}
			return services
		},
	); err != nil {
		return err
	}

	b := ctrl.NewControllerManagedBy(mgr).
		// By default, controllers are named using the lowercase version of their kind.
		// For Gamma, we want to avoid conflict with existing HTTPRoute controller.
		Named(strings.ToLower(gammaHTTPRoute)).
		// Watch for changes to HTTPRoute
		For(&gatewayv1.HTTPRoute{},
			builder.WithPredicates(predicate.NewPredicateFuncs(r.hasGammaParent()))).
		// Watch for changes to Backend services
		Watches(&corev1.Service{}, r.enqueueRequestForBackendService()).
		// Watch for changes to GAMMA Listening services
		Watches(&corev1.Service{}, r.enqueueRequestForGammaService()).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1beta1.ReferenceGrant{}, r.enqueueRequestForReferenceGrant())

	return b.Complete(r)
}

func (r *gammaHttpRouteReconciler) hasGammaParent() func(object client.Object) bool {
	return func(obj client.Object) bool {
		hr, ok := obj.(*gatewayv1.HTTPRoute)
		if !ok {
			return false
		}

		for _, parent := range hr.Spec.ParentRefs {
			if helpers.IsGammaService(parent) {
				return true
			}
		}

		return false
	}
}

// enqueueRequestForBackendService makes sure that HTTP Routes are reconciled
// if the backend services are updated.
func (r *gammaHttpRouteReconciler) enqueueRequestForBackendService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gammaBackendServiceIndex))
}

// enqueueRequestForReferenceGrant makes sure that all HTTP Routes are reconciled
// if a ReferenceGrant changes
func (r *gammaHttpRouteReconciler) enqueueRequestForReferenceGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueAll())
}

func (r *gammaHttpRouteReconciler) enqueueRequestForGammaService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gammaListenerServiceIndex))
}

func (r *gammaHttpRouteReconciler) enqueueFromIndex(index string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, gammaHTTPRoute, logfields.Resource, client.ObjectKeyFromObject(o))
		hrList := &gatewayv1.HTTPRouteList{}

		if err := r.Client.List(ctx, hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.Error("Failed to get related HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(hrList.Items))
		for _, item := range hrList.Items {
			route := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: route,
			})
			scopedLog.Info("Enqueued HTTPRoute for resource", httpRoute, route)
		}
		return requests
	}
}

func (r *gammaHttpRouteReconciler) enqueueAll() handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, gammaHTTPRoute, logfields.Resource, client.ObjectKeyFromObject(o))

		hrList := &gatewayv1.HTTPRouteList{}

		if err := r.Client.List(ctx, hrList, &client.ListOptions{}); err != nil {
			scopedLog.Error("Failed to get HTTPRoutes", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(hrList.Items))
		for _, item := range hrList.Items {
			route := client.ObjectKey{
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
			}
			requests = append(requests, reconcile.Request{
				NamespacedName: route,
			})
			scopedLog.Info("Enqueued HTTPRoute for resource", httpRoute, route)
		}
		return requests
	}
}
