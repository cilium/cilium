// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
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
		gatewayClassConfigMapIndexName: referencedConfigMap,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GatewayClass{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.GatewayClass{},
			builder.WithPredicates(predicate.NewPredicateFuncs(matchesControllerName(controllerName)))).
		Watches(&corev1.ConfigMap{}, r.enqueueRequestForConfigMap()).
		Complete(r)
}

func (r *gatewayClassReconciler) enqueueRequestForConfigMap() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(r.enqueueFromIndex(gatewayClassConfigMapIndexName))
}

func (r *gatewayClassReconciler) enqueueFromIndex(index string) handler.MapFunc {
	return func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := r.logger.With(logfields.Controller, gatewayClass, logfields.Resource, client.ObjectKeyFromObject(o))
		list := &gatewayv1.GatewayClassList{}

		if err := r.Client.List(ctx, list, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(index, client.ObjectKeyFromObject(o).String()),
		}); err != nil {
			scopedLog.Error("Failed to list related GatewayClass", logfields.Error, err)
			return []reconcile.Request{}
		}

		requests := make([]reconcile.Request, 0, len(list.Items))
		for _, item := range list.Items {
			c := client.ObjectKeyFromObject(&item)
			requests = append(requests, reconcile.Request{NamespacedName: c})
			scopedLog.Info("Enqueued GatewayClass for resource", gatewayClass, c)
		}
		return requests
	}
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

// referencedConfigMap returns a list of ConfigMap names referenced by the GatewayClass.
func referencedConfigMap(rawObj client.Object) []string {
	gwc, ok := rawObj.(*gatewayv1.GatewayClass)
	if !ok {
		return nil
	}

	if gwc.Spec.ParametersRef == nil ||
		gwc.Spec.ParametersRef.Group != "v1" || gwc.Spec.ParametersRef.Kind != "ConfigMap" ||
		gwc.Spec.ParametersRef.Namespace == nil || gwc.Spec.ParametersRef.Name == "" {
		return nil
	}

	return []string{types.NamespacedName{
		Namespace: string(*gwc.Spec.ParametersRef.Namespace),
		Name:      gwc.Spec.ParametersRef.Name,
	}.String()}
}
