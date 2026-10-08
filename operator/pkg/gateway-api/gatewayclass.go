// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/predicates"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// gatewayClassReconciler reconciles a GatewayClass object
type gatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	logger         *slog.Logger
	controllerName string
}

func newGatewayClassReconciler(mgr ctrl.Manager, logger *slog.Logger, controllerName string) *gatewayClassReconciler {
	return &gatewayClassReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		logger:         logger,
		controllerName: controllerName,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *gatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		// Index GatewayClass objects by the referenced CiliumGatewayClassConfig.
		indexers.GatewayClassCiliumGatewayClassConfigsIndex: indexers.IndexGatewayClassByCiliumGatewayClassConfig(gatewayv1.GatewayController(r.controllerName)),
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GatewayClass{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{},
			builder.WithPredicates(predicates.GatewayClassOwnedByController(r.controllerName))).
		Watches(&v2alpha1.CiliumGatewayClassConfig{}, watchhandlers.EnqueueRequestForCiliumGatewayClassConfig(r.Client, r.logger)).
		Complete(r)
}
