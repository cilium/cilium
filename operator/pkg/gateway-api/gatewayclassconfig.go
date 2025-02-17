// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// gatewayClassReconciler reconciles a GatewayClass object
type gatewayClassConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	logger *slog.Logger
}

func newGatewayClassConfigReconciler(mgr ctrl.Manager, logger *slog.Logger) *gatewayClassConfigReconciler {
	return &gatewayClassConfigReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		logger: logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *gatewayClassConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v2alpha1.CiliumGatewayClassConfig{}).
		Complete(r)
}
