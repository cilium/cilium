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
	"sigs.k8s.io/controller-runtime/pkg/source"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// tlsRouteReconciler reconciles a TLSRoute object
type tlsRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel
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
					if !IsService(backend.BackendObjectReference) {
						continue
					}
					backendServices = append(backendServices,
						types.NamespacedName{
							Namespace: namespaceDerefOr(backend.Namespace, hr.Namespace),
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
				if !IsGateway(parent) {
					continue
				}
				gateways = append(gateways,
					types.NamespacedName{
						Namespace: namespaceDerefOr(parent.Namespace, hr.Namespace),
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
		Watches(&source.Kind{Type: &corev1.Service{}}, r.enqueueRequestForBackendService()).
		// Watch for changes to Gateways and enqueue TLSRoutes that reference them
		Watches(&source.Kind{Type: &gatewayv1beta1.Gateway{}}, r.enqueueRequestForGateway()).
		// Watch for changes to Gateways and enqueue TLSRoutes that reference them,
		Watches(&source.Kind{Type: &gatewayv1beta1.Gateway{}}, r.enqueueRequestForGateway(),
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

func (r *tlsRouteReconciler) enqueueRequestForGateway() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayIndex))
}

func (r *tlsRouteReconciler) enqueueFromIndex(index string) handler.MapFunc {
	return func(o client.Object) []reconcile.Request {
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
