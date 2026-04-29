// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/predicates"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	gatewayClassConfigMapIndexName = ".spec.parametersRef"
)

// gatewayClassReconciler reconciles a GatewayClass object
type gatewayClassReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	logger *slog.Logger
}

func newGatewayClassReconciler(mgr ctrl.Manager, logger *slog.Logger) *gatewayClassReconciler {
	return &gatewayClassReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		logger: logger,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *gatewayClassReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		gatewayClassConfigMapIndexName: referencedConfig,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GatewayClass{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{},
			builder.WithPredicates(predicates.GatewayClassOwnedByController(helpers.CiliumDefaultControllerName))).
		Watches(&v2alpha1.CiliumGatewayClassConfig{}, watchhandlers.EnqueueRequestForCiliumGatewayClassConfig(r.Client, r.logger)).
		Complete(r)
}

func matchesControllerName(controllerName string) func(object client.Object) bool {
	return func(object client.Object) bool {
		gwc, ok := object.(*gatewayv1.GatewayClass)
		if !ok {
			return false
		}
		return string(gwc.Spec.ControllerName) == controllerName
	}
}

// referencedConfig returns a list of CiliumGatewayClassConfig names referenced by the GatewayClass.
func referencedConfig(rawObj client.Object) []string {
	gwc, ok := rawObj.(*gatewayv1.GatewayClass)
	if !ok {
		return nil
	}

	if !isParameterRefSupported(gwc.Spec.ParametersRef) {
		return nil
	}

	if gwc.Spec.ParametersRef.Namespace == nil {
		return nil
	}

	return []string{types.NamespacedName{
		Namespace: string(*gwc.Spec.ParametersRef.Namespace),
		Name:      gwc.Spec.ParametersRef.Name,
	}.String()}
}
