// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// UpdateReconcileRequestsForParentRefs mutates the passed reconcile.Request set
// to add all referenced Gateways, both via Gateway and via ListenerSet.
func UpdateReconcileRequestsForParentRefs(ctx context.Context, c client.Client, parentRefs []gatewayv1.ParentReference, ns string, allGatewaysSet map[string]struct{}, rrSet map[reconcile.Request]struct{}) {
	for _, parent := range parentRefs {
		if IsGateway(parent) {
			parentFullName := types.NamespacedName{
				Name:      string(parent.Name),
				Namespace: NamespaceDerefOr(parent.Namespace, ns),
			}
			if _, found := allGatewaysSet[parentFullName.String()]; found {
				rrSet[reconcile.Request{NamespacedName: parentFullName}] = struct{}{}
			}
			continue
		}

		if IsListenerSet(parent) {
			gwNN := ResolveListenerSetToGateway(ctx, c, string(parent.Name), NamespaceDerefOr(parent.Namespace, ns))
			if gwNN != nil {
				if _, found := allGatewaysSet[gwNN.String()]; found {
					rrSet[reconcile.Request{NamespacedName: *gwNN}] = struct{}{}
				}
			}
		}
	}
}
