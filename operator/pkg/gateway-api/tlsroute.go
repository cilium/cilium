// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/sirupsen/logrus"
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

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// tlsRouteReconciler reconciles a TLSRoute object
type tlsRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func newTLSRouteReconciler(mgr ctrl.Manager) *tlsRouteReconciler {
	return &tlsRouteReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *tlsRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TLSRoute{}, backendServiceIndex,
		func(rawObj client.Object) []string {
			hr, ok := rawObj.(*gatewayv1alpha2.TLSRoute)
			if !ok {
				return nil
			}
			var backendServices []string
			for _, rule := range hr.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if !helpers.IsService(backend.BackendObjectReference) {
						continue
					}
					backendServices = append(backendServices,
						types.NamespacedName{
							Namespace: helpers.NamespaceDerefOr(backend.Namespace, hr.Namespace),
							Name:      string(backend.Name),
						}.String(),
					)
				}
			}
			return backendServices
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

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changes to TLSRoute
		For(&gatewayv1alpha2.TLSRoute{}).
		// Watch for changes to Backend services
		Watches(&corev1.Service{}, r.enqueueRequestForBackendService()).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1alpha2.ReferenceGrant{}, r.enqueueRequestForRequestGrant()).
		// Watch for changes to Gateways and enqueue TLSRoutes that reference them,
		Watches(&gatewayv1.Gateway{}, r.enqueueRequestForGateway(),
			builder.WithPredicates(
				predicate.NewPredicateFuncs(hasMatchingController(context.Background(), mgr.GetClient(), controllerName)),
			)).
		Complete(r)
}

// enqueueRequestForBackendService makes sure that TLS Routes are reconciled
// if the backend services are updated.
func (r *tlsRouteReconciler) enqueueRequestForBackendService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(backendServiceIndex))
}

// enqueueRequestForRequestGrant makes sure that TLS Routes in the same namespace are reconciled
func (r *tlsRouteReconciler) enqueueRequestForRequestGrant() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueAll())
}

func (r *tlsRouteReconciler) enqueueRequestForGateway() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayIndex))
}

func (r *tlsRouteReconciler) enqueueFromIndex(index string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "tlsRoute",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})
		rList := &gatewayv1alpha2.TLSRouteList{}

		if err := r.Client.List(context.Background(), rList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.WithError(err).Error("Failed to get related TLSRoutes")
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
			scopedLog.WithField("tlsRoute", route).Info("Enqueued TLSRoute for resource")
		}
		return requests
	}
}

func (r *tlsRouteReconciler) enqueueAll() handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "tlsRoute",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})
		trList := &gatewayv1alpha2.TLSRouteList{}

		if err := r.Client.List(ctx, trList, &client.ListOptions{}); err != nil {
			scopedLog.WithError(err).Error("Failed to get TLSRoutes")
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
			scopedLog.WithField("tlsRoute", route).Info("Enqueued TLSRoute for resource")
		}
		return requests
	}
}
