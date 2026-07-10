// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// updateReconcileRequestsForParentRefs mutates the passed reconcile.Request set
// to add all referenced Gateways, both via Gateway and via ListenerSet
func updateReconcileRequestsForParentRefs(ctx context.Context, c client.Client, parentRefs []gatewayv1.ParentReference, ns string, allGatewaysSet map[string]struct{}, rrSet map[reconcile.Request]struct{}) {
	for _, parent := range parentRefs {
		if helpers.IsGateway(parent) {
			parentFullName := types.NamespacedName{
				Name:      string(parent.Name),
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, ns),
			}
			if _, found := allGatewaysSet[parentFullName.String()]; found {
				rrSet[reconcile.Request{NamespacedName: parentFullName}] = struct{}{}
			}
			continue
		}

		if helpers.IsListenerSet(parent) {
			gwNN := helpers.ResolveListenerSetToGateway(ctx, c, string(parent.Name), helpers.NamespaceDerefOr(parent.Namespace, ns))
			if gwNN != nil {
				if _, found := allGatewaysSet[gwNN.String()]; found {
					rrSet[reconcile.Request{NamespacedName: *gwNN}] = struct{}{}
				}
			}
		}
	}
}

func hasMatchingController(ctx context.Context, c client.Client, controllerName string, logger *slog.Logger) func(object client.Object) bool {
	return func(obj client.Object) bool {
		scopedLog := logger.With(
			logfields.Resource, obj.GetName(),
		)
		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			return false
		}

		gwc := &gatewayv1.GatewayClass{}
		key := types.NamespacedName{Name: string(gw.Spec.GatewayClassName)}
		if err := c.Get(ctx, key, gwc); err != nil {
			scopedLog.ErrorContext(ctx, "Unable to get GatewayClass", logfields.Error, err)
			return false
		}

		return string(gwc.Spec.ControllerName) == controllerName
	}
}

func getGatewayReconcileRequestsForRoute(ctx context.Context, c client.Client, object metav1.Object, route gatewayv1.CommonRouteSpec, logger *slog.Logger, controllerName string) []reconcile.Request {
	var reqs []reconcile.Request

	scopedLog := logger.With(
		logfields.Resource, types.NamespacedName{
			Namespace: object.GetNamespace(),
			Name:      object.GetName(),
		},
	)

	for _, parent := range route.ParentRefs {
		var gwNN types.NamespacedName

		switch {
		case helpers.IsGateway(parent):
			gwNN = types.NamespacedName{
				Namespace: helpers.NamespaceDerefOr(parent.Namespace, object.GetNamespace()),
				Name:      string(parent.Name),
			}
		case helpers.IsListenerSet(parent):
			resolved := helpers.ResolveListenerSetToGateway(ctx, c, string(parent.Name), helpers.NamespaceDerefOr(parent.Namespace, object.GetNamespace()))
			if resolved == nil {
				continue
			}
			gwNN = *resolved
		default:
			continue
		}

		gw := &gatewayv1.Gateway{}
		if err := c.Get(ctx, gwNN, gw); err != nil {
			if !k8serrors.IsNotFound(err) {
				scopedLog.ErrorContext(ctx, "Failed to get Gateway", logfields.Error, err)
			}
			continue
		}

		if !hasMatchingController(ctx, c, controllerName, logger)(gw) {
			scopedLog.DebugContext(ctx, "Gateway does not have matching controller, skipping")
			continue
		}

		scopedLog.InfoContext(ctx,
			"Enqueued gateway for Route",
			logfields.K8sNamespace, gwNN.Namespace,
			logfields.ParentResource, gwNN.Name,
			logfields.Route, object.GetName())

		reqs = append(reqs, reconcile.Request{
			NamespacedName: gwNN,
		})
	}

	return reqs
}

func getAllCiliumGatewaysSet(ctx context.Context, c client.Client) (map[string]struct{}, error) {
	// Fetch all the Cilium-relevant Gateways using the indexers.ImplementationGatewayIndex.
	gwList := &gatewayv1.GatewayList{}
	if err := c.List(ctx, gwList, &client.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(indexers.ImplementationGatewayIndex, "cilium"),
	}); err != nil {
		return nil, err
	}
	// Build a set of all Cilium Gateway full names.
	// This makes sure we only add a reconcile.Request once for each Gateway.
	allCiliumGatewaysSet := make(map[string]struct{})

	for _, gw := range gwList.Items {
		gwFullName := types.NamespacedName{
			Name:      gw.GetName(),
			Namespace: gw.GetNamespace(),
		}
		allCiliumGatewaysSet[gwFullName.String()] = struct{}{}
	}

	return allCiliumGatewaysSet, nil
}
