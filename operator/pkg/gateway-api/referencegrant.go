// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// referenceGrantReconciler reconciles a ReferenceGrant object
type referenceGrantReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	Model *internalModel
}

// SetupWithManager sets up the controller with the Manager.
func (r *referenceGrantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1beta1.ReferenceGrant{}).
		Complete(r)
}
