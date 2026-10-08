// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

func GatewayOwnedByController(hasMatchingControllerFn func(object client.Object) bool) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return hasMatchingControllerFn(e.Object)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return hasMatchingControllerFn(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Reconcile one last time when a Gateway moves away from this controller
			// so previously managed resources can be cleaned up.
			return hasMatchingControllerFn(e.ObjectOld) || hasMatchingControllerFn(e.ObjectNew)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasMatchingControllerFn(e.Object)
		},
	}
}
