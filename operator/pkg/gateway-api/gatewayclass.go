// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// gatewayClassReconciler reconciles a GatewayClass object
type gatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel

	controllerName string
}

// SetupWithManager sets up the controller with the Manager.
func (r *gatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1beta1.GatewayClass{},
			builder.WithPredicates(predicate.NewPredicateFuncs(matchesControllerName(r.controllerName)))).
		Complete(r)
}

func matchesControllerName(controllerName string) func(object client.Object) bool {
	return func(object client.Object) bool {
		gwc, ok := object.(*gatewayv1beta1.GatewayClass)
		if !ok {
			return false
		}
		return string(gwc.Spec.ControllerName) == controllerName
	}
}
