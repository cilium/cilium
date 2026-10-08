// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func GatewayClassOwnedByController(controllerName string) predicate.Predicate {
	hasMatchingControllerName := helpers.GatewayClassMatchesControllerName(controllerName)
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return hasMatchingControllerName(e.Object)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return hasMatchingControllerName(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Reconcile one last time when a GatewayClass moves away from this controller
			// so referenced Gateways can clean up previously managed resources.
			return hasMatchingControllerName(e.ObjectOld) || hasMatchingControllerName(e.ObjectNew)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasMatchingControllerName(e.Object)
		},
	}
}
