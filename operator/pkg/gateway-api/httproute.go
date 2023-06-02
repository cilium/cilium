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
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	backendServiceIndex = "backendServiceIndex"
	gatewayIndex        = "gatewayIndex"
)

type httpRouteChecker func(ctx context.Context, client client.Client, hr *gatewayv1beta1.HTTPRoute) (ctrl.Result, error)

// httpRouteReconciler reconciles a HTTPRoute object
type httpRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel
}

// SetupWithManager sets up the controller with the Manager.
func (r *httpRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1beta1.HTTPRoute{}, backendServiceIndex,
		func(rawObj client.Object) []string {
			hr, ok := rawObj.(*gatewayv1beta1.HTTPRoute)
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

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1beta1.HTTPRoute{}, gatewayIndex,
		func(rawObj client.Object) []string {
			hr := rawObj.(*gatewayv1beta1.HTTPRoute)
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
		// Watch for changes to HTTPRoute
		For(&gatewayv1beta1.HTTPRoute{}).
		// Watch for changes to Backend services
		Watches(&source.Kind{Type: &corev1.Service{}}, r.enqueueRequestForBackendService()).
		// Watch for changes to Gateways and enqueue HTTPRoutes that reference them,
		Watches(&source.Kind{Type: &gatewayv1beta1.Gateway{}}, r.enqueueRequestForGateway(),
			builder.WithPredicates(
				predicate.NewPredicateFuncs(hasMatchingController(context.Background(), mgr.GetClient(), controllerName)))).
		Complete(r)
}

// enqueueRequestForBackendService makes sure that HTTP Routes are reconciled
// if the backend services are updated.
func (r *httpRouteReconciler) enqueueRequestForBackendService() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(backendServiceIndex))
}

func (r *httpRouteReconciler) enqueueRequestForGateway() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayIndex))
}

func (r *httpRouteReconciler) enqueueFromIndex(index string) func(o client.Object) []reconcile.Request {
	return func(o client.Object) []reconcile.Request {
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Controller: "httpRoute",
			logfields.Resource:   client.ObjectKeyFromObject(o),
		})
		hrList := &gatewayv1beta1.HTTPRouteList{}

		if err := r.Client.List(context.Background(), hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.WithError(err).Error("Failed to get related HTTPRoutes")
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
			scopedLog.WithField("httpRoute", route).Info("Enqueued HTTPRoute for resource")
		}
		return requests
	}
}
