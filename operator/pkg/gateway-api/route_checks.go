// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// TODO(https://github.com/cilium/cilium/issues/25130): turn this into a generic checker that can be used for all route types
type backendValidationFunc func(ctx context.Context, log *logrus.Entry, c client.Client, tr *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error)

func checkAgainstCrossNamespaceReferences(ctx context.Context, log *logrus.Entry, c client.Client, tr *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	continueChecks := true

	for _, rule := range tr.Spec.Rules {
		for _, be := range rule.BackendRefs {
			ns := namespaceDerefOr(be.Namespace, tr.GetNamespace())
			if ns != tr.GetNamespace() {
				for _, parent := range tr.Spec.ParentRefs {
					mergeTLSRouteStatusConditions(tr, parent, []metav1.Condition{
						tlsRefNotPermittedRouteCondition(tr, "Cross namespace references are not allowed"),
					})
				}
				continueChecks = false
			}
		}
	}
	return ctrl.Result{}, continueChecks, nil
}

func checkBackendIsService(ctx context.Context, log *logrus.Entry, c client.Client, tr *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	continueChecks := true

	for _, rule := range tr.Spec.Rules {
		for _, be := range rule.BackendRefs {
			if !IsService(be.BackendObjectReference) {
				for _, parent := range tr.Spec.ParentRefs {
					mergeTLSRouteStatusConditions(tr, parent, []metav1.Condition{
						tlsInvalidKindRouteCondition(tr, string("Unsupported backend kind "+*be.Kind)),
					})
				}
				continue
			}

		}
	}

	return ctrl.Result{}, continueChecks, nil
}

func checkBackendIsExistingService(ctx context.Context, log *logrus.Entry, c client.Client, tr *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	continueChecks := true

	for _, rule := range tr.Spec.Rules {
		for _, be := range rule.BackendRefs {
			svc := &corev1.Service{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: tr.GetNamespace(), Name: string(be.Name)}, svc); err != nil {
				if !k8serrors.IsNotFound(err) {
					log.WithError(err).Error("Failed to get Service")
					return ctrl.Result{}, false, err
				}
				// Service does not exist, update the status for all the parents
				// The `Accepted` condition on a route only describes whether
				// the route attached successfully to its parent, so no error
				// is returned here, so that the next validation can be run.
				for _, parent := range tr.Spec.ParentRefs {
					mergeTLSRouteStatusConditions(tr, parent, []metav1.Condition{
						tlsBackendNotFoundRouteCondition(tr, err.Error()),
					})
				}
			}
		}
	}

	return ctrl.Result{}, continueChecks, nil
}

// TODO(https://github.com/cilium/cilium/issues/25130): turn this into a generic checker that can be used for all route types + add ReferenceGrants check
type gatewayParentValidatonFunc func(ctx context.Context, log *logrus.Entry, c client.Client, parentRef gatewayv1alpha2.ParentReference, gw *gatewayv1beta1.Gateway, route *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error)

func checkGatewayAllowedForNamespace(ctx context.Context, log *logrus.Entry, c client.Client, parentRef gatewayv1alpha2.ParentReference, gw *gatewayv1beta1.Gateway, route *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	for _, listener := range gw.Spec.Listeners {

		if listener.AllowedRoutes != nil {
			continue
		}

		if listener.AllowedRoutes.Namespaces == nil {
			continue
		}

		if *listener.AllowedRoutes.Namespaces.From == gatewayv1beta1.NamespacesFromSelector {
			nsList := &corev1.NamespaceList{}
			selector, _ := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
			if err := c.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
				return ctrl.Result{}, false, fmt.Errorf("unable to list namespaces: %w", err)
			}

			allowed := false
			for _, ns := range nsList.Items {
				if ns.Name == route.GetNamespace() {
					allowed = true
				}
			}
			if !allowed {
				mergeTLSRouteStatusConditions(route, parentRef, []metav1.Condition{
					tlsRouteAcceptedCondition(route, false, "TLSRoute is not allowed to attach to this Gateway due to namespace selector restrictions"),
				})
				return ctrl.Result{}, false, nil
			}
		}

		// if gateway allows all namespaces, we do not need to check anything here
		if *listener.AllowedRoutes.Namespaces.From == gatewayv1beta1.NamespacesFromAll {
			continue
		}

		// check if the gateway allows the same namespace as the route
		if *listener.AllowedRoutes.Namespaces.From == gatewayv1beta1.NamespacesFromSame &&
			route.GetNamespace() == gw.GetNamespace() {
			mergeTLSRouteStatusConditions(route, parentRef, []metav1.Condition{
				tlsRouteAcceptedCondition(route, false, "TLSRoute is not allowed to attach to this Gateway due to namespace restrictions"),
			})
			return ctrl.Result{}, false, nil
		}
	}

	return ctrl.Result{}, true, nil
}

func checkGatewayRouteKindAllowed(ctx context.Context, log *logrus.Entry, c client.Client, parentRef gatewayv1alpha2.ParentReference, gw *gatewayv1beta1.Gateway, route *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	for _, listener := range gw.Spec.Listeners {
		if listener.AllowedRoutes.Kinds == nil {
			continue
		}

		allowed := false
		routeKind := getGatewayKindForObject(route)
		for _, kind := range listener.AllowedRoutes.Kinds {
			if (kind.Group == nil || string(*kind.Group) == gatewayv1beta1.GroupName) &&
				kind.Kind == kindHTTPRoute && routeKind == kindHTTPRoute {
				allowed = true
			} else if (kind.Group == nil || string(*kind.Group) == gatewayv1alpha2.GroupName) &&
				kind.Kind == kindTLSRoute && routeKind == kindTLSRoute {
				allowed = true
			}
		}

		if !allowed {
			mergeTLSRouteStatusConditions(route, parentRef, []metav1.Condition{
				RouteReasonNotAllowedByListeners(route, "TLSRoute is not allowed to attach to this Gateway due to route kind restrictions"),
			})
			return ctrl.Result{}, false, nil
		}
	}

	return ctrl.Result{}, true, nil
}

func checkMatchingGatewayHostnames(ctx context.Context, log *logrus.Entry, c client.Client, parentRef gatewayv1alpha2.ParentReference, gw *gatewayv1beta1.Gateway, route *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	if len(computeHosts(gw, route.Spec.Hostnames)) == 0 {
		mergeTLSRouteStatusConditions(route, parentRef, []metav1.Condition{
			tlsNoMatchingListenerHostnameRouteCondition(route, "No matching listener hostname"),
		})

		return ctrl.Result{}, false, nil
	}

	return ctrl.Result{}, true, nil
}

func checkMatchingGatewayPorts(ctx context.Context, log *logrus.Entry, c client.Client, parentRef gatewayv1alpha2.ParentReference, gw *gatewayv1beta1.Gateway, route *gatewayv1alpha2.TLSRoute) (ctrl.Result, bool, error) {
	if parentRef.Port != nil {
		for _, listener := range gw.Spec.Listeners {
			if listener.Port == *parentRef.Port {
				return ctrl.Result{}, true, nil
			}
		}

		mergeTLSRouteStatusConditions(route, parentRef, []metav1.Condition{
			tlsNoMatchingListenerPortCondition(route, fmt.Sprintf("No matching listener with port %d", *parentRef.Port)),
		})
		return ctrl.Result{}, false, nil
	}

	return ctrl.Result{}, true, nil
}
