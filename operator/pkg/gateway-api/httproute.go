// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// httpRouteReconciler reconciles a HTTPRoute object
type httpRouteReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *httpRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "httproute",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling HTTPRoute")

	// Fetch the HTTPRoute instance
	original := &gatewayv1beta1.HTTPRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		return fail(err)
	}

	// Ignore deleted HTTPRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return success()
	}

	hr := original.DeepCopy()

	for _, parent := range hr.Spec.ParentRefs {
		ns := namespaceDerefOr(parent.Namespace, hr.GetNamespace())
		gw := &gatewayv1beta1.Gateway{}
		if err := r.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				return fail(err)
			}
			// Gateway does not exist, update the status for this gateway
			mergeHTTPRouteStatusConditions(&hr.Status.RouteStatus, parent, []metav1.Condition{
				httpRouteAcceptedCondition(hr, false, "Gateway does not exist"),
			})
			continue
		}

		if !isAttachable(ctx, r.Client, gw, hr) {
			// Gateway is not attachable, update the status for this HTTPRoute
			mergeHTTPRouteStatusConditions(&hr.Status.RouteStatus, parent, []metav1.Condition{
				httpRouteAcceptedCondition(hr, false, "HTTPRoute is not allowed"),
			})
			continue
		}

		// Gateway is attachable, update the status for this HTTPRoute
		mergeHTTPRouteStatusConditions(&hr.Status.RouteStatus, parent, []metav1.Condition{
			httpRouteAcceptedCondition(hr, true, httpRouteAcceptedMessage),
		})
	}

	if err := r.updateStatus(ctx, original, hr); err != nil {
		scopedLog.WithError(err).Error("Failed to update HTTPRoute status")
		return fail(err)
	}

	scopedLog.Info("Successfully reconciled HTTPRoute")
	return success()
}

func (r *httpRouteReconciler) updateStatus(ctx context.Context, original *gatewayv1beta1.HTTPRoute, new *gatewayv1beta1.HTTPRoute) error {
	oldStatus := original.Status.DeepCopy()
	newStatus := new.Status.DeepCopy()

	opts := cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime")
	if cmp.Equal(oldStatus, newStatus, opts) {
		return nil
	}
	return r.Client.Status().Update(ctx, new)
}

// SetupWithManager sets up the controller with the Manager.
func (r *httpRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1beta1.HTTPRoute{}, backendServiceIndex,
		func(rawObj client.Object) []string {
			hr := rawObj.(*gatewayv1beta1.HTTPRoute)
			var backendServices []string
			for _, rule := range hr.Spec.Rules {
				for _, backend := range rule.BackendRefs {
					if string(*backend.Kind) == kindService {
						backendServices = append(backendServices,
							types.NamespacedName{
								Namespace: namespaceDerefOr(backend.Namespace, hr.Namespace),
								Name:      string(backend.Name),
							}.String(),
						)
					}
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
				if parent.Kind != nil && string(*parent.Kind) == kindGateway &&
					parent.Group != nil && string(*parent.Group) == gatewayv1beta1.GroupName {
					gateways = append(gateways,
						types.NamespacedName{
							Namespace: namespaceDerefOr(parent.Namespace, hr.Namespace),
							Name:      string(parent.Name),
						}.String(),
					)
				}
			}
			return gateways
		},
	); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		// Watch for changes to HTTPRoute, but not the status
		For(&gatewayv1beta1.HTTPRoute{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Watch for changes to Backend services
		Watches(&source.Kind{Type: &corev1.Service{}}, r.enqueueRequestForBackendService()).
		// Watch for changes to Gateways and enqueue HTTPRoutes that reference them,
		// only if there is a change in the spec
		Watches(&source.Kind{Type: &gatewayv1beta1.Gateway{}}, r.enqueueRequestForGateway(),
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
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
			logfields.Controller: "httproute",
			logfields.Resource:   o.GetName(),
		})
		hrList := &gatewayv1beta1.HTTPRouteList{}

		if err := r.Client.List(context.Background(), hrList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.WithError(err).Error("Failed to get affected HTTPRoutes")
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(hrList.Items))
		for _, item := range hrList.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{
					Namespace: item.GetNamespace(),
					Name:      item.GetName(),
				},
			})
		}
		return requests
	}
}
