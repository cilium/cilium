// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *httpRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "httpRoute",
		logfields.Resource:   req.NamespacedName,
	})
	scopedLog.Info("Reconciling HTTPRoute")

	// Fetch the HTTPRoute instance
	original := &gatewayv1beta1.HTTPRoute{}
	if err := r.Client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			return success()
		}
		scopedLog.WithError(err).Error("Unable to fetch HTTPRoute")
		return fail(err)
	}

	// Ignore deleted HTTPRoute, this can happen when foregroundDeletion is enabled
	if original.GetDeletionTimestamp() != nil {
		return success()
	}

	hr := original.DeepCopy()
	defer func() {
		if err := r.updateStatus(ctx, original, hr); err != nil {
			scopedLog.WithError(err).Error("Failed to update HTTPRoute status")
		}
	}()

	for _, fn := range []httpRouteChecker{
		validateService,
		validateGateway,
	} {
		if res, err := fn(ctx, r.Client, hr); err != nil {
			return res, err
		}
	}

	scopedLog.Info("Successfully reconciled HTTPRoute")
	return success()
}

func validateService(ctx context.Context, c client.Client, hr *gatewayv1beta1.HTTPRoute) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "httpRoute",
		logfields.Resource:   client.ObjectKeyFromObject(hr),
	})

	for _, rule := range hr.Spec.Rules {
		for _, be := range rule.BackendRefs {
			ns := namespaceDerefOr(be.Namespace, hr.GetNamespace())
			if ns != hr.GetNamespace() {
				for _, parent := range hr.Spec.ParentRefs {
					mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
						httpRefNotPermittedRouteCondition(hr, "Cross namespace references are not allowed"),
					})
				}
				continue
			}

			if !IsService(be.BackendObjectReference) {
				for _, parent := range hr.Spec.ParentRefs {
					mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
						httpInvalidKindRouteCondition(hr, string("Unsupported backend kind "+*be.Kind)),
					})
				}
				continue
			}

			svc := &corev1.Service{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(be.Name)}, svc); err != nil {
				if !k8serrors.IsNotFound(err) {
					scopedLog.WithError(err).Error("Failed to get Service")
					return fail(err)
				}
				// Service does not exist, update the status for all the parents
				// The `Accepted` condition on a route only describes whether
				// the route attached successfully to its parent, so no error
				// is returned here, so that the next validation can be run.
				for _, parent := range hr.Spec.ParentRefs {
					mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
						httpBackendNotFoundRouteCondition(hr, err.Error()),
					})
				}
			}
		}
	}
	return success()
}

func validateGateway(ctx context.Context, c client.Client, hr *gatewayv1beta1.HTTPRoute) (ctrl.Result, error) {
	scopedLog := log.WithContext(ctx).WithFields(logrus.Fields{
		logfields.Controller: "httpRoute",
		logfields.Resource:   client.ObjectKeyFromObject(hr),
	})

	for _, parent := range hr.Spec.ParentRefs {
		ns := namespaceDerefOr(parent.Namespace, hr.GetNamespace())
		gw := &gatewayv1beta1.Gateway{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(parent.Name)}, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
					httpRouteAcceptedCondition(hr, false, err.Error()),
				})
				return fail(err)
			}
			// Gateway does not exist, update the status for this HTTPRoute
			mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
				httpRouteAcceptedCondition(hr, false, err.Error()),
			})
			continue
		}

		if !hasMatchingController(ctx, c, controllerName)(gw) {
			continue
		}

		if !isAllowed(ctx, c, gw, hr) {
			// Gateway is not attachable, update the status for this HTTPRoute
			mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
				httpRouteNotAllowedByListenersCondition(hr, "HTTPRoute is not allowed"),
			})
			continue
		}

		if parent.Port != nil {
			found := false
			for _, listener := range gw.Spec.Listeners {
				if listener.Port == *parent.Port {
					found = true
					break
				}
			}
			if !found {
				mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
					httpNoMatchingListenerPortCondition(hr, fmt.Sprintf("No matching listener with port %d", *parent.Port)),
				})
				continue
			}
		}

		if len(computeHosts(gw, hr.Spec.Hostnames)) == 0 {
			// No matching host, update the status for this HTTPRoute
			mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
				httpNoMatchingListenerHostnameRouteCondition(hr, "No matching listener hostname"),
			})
			continue
		}

		scopedLog.Debug("HTTPRoute is attachable")
		// Gateway is attachable, update the status for this HTTPRoute
		mergeHTTPRouteStatusConditions(hr, parent, []metav1.Condition{
			httpRouteAcceptedCondition(hr, true, httpRouteAcceptedMessage),
		})
	}
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
