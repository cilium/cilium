// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// Deprecated: owningGatewayLabel will be removed later in favour of gatewayNameLabel
	owningGatewayLabel = "io.cilium.gateway/owning-gateway"

	lastTransitionTime = "LastTransitionTime"
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	logger        *slog.Logger
	installedCRDs []schema.GroupVersionKind
}

func newGatewayReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger, installedCRDs []schema.GroupVersionKind) *gatewayReconciler {
	scopedLog := logger.With(logfields.Controller, gateway)

	return &gatewayReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		translator:    translator,
		logger:        scopedLog,
		installedCRDs: installedCRDs,
	}
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Determine which optional CRDs are enabled
	var tlsRouteEnabled, serviceImportEnabled bool

	for _, gvk := range r.installedCRDs {
		switch gvk.Kind {
		case helpers.TLSRouteKind:
			tlsRouteEnabled = true
		case helpers.ServiceImportKind:
			serviceImportEnabled = true
		}
	}

	// Add field indexes for HTTPRoutes
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		indexers.BackendServiceHTTPRouteIndex: indexers.GenerateIndexerHTTPRouteByBackendService(r.Client, r.logger),
		indexers.GatewayHTTPRouteIndex:        indexers.IndexHTTPRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	// Only index HTTPRoute by ServiceImport if ServiceImport is enabled
	if serviceImportEnabled {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexers.BackendServiceImportHTTPRouteIndex, indexers.IndexHTTPRouteByBackendServiceImport); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendServiceImportHTTPRouteIndex, err)
		}
	}

	// Index Gateways by implementation (ie `cilium`)
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, indexers.ImplementationGatewayIndex, indexers.GenerateIndexerGatewayByImplementation(r.Client, controllerName)); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", indexers.ImplementationGatewayIndex, err)
	}

	// Add indexes for TLSRoutes
	if tlsRouteEnabled {
		for indexName, indexerFunc := range map[string]client.IndexerFunc{
			indexers.BackendServiceTLSRouteIndex: indexers.GenerateIndexerTLSRoutebyBackendService(r.Client, r.logger),
			indexers.GatewayTLSRouteIndex:        indexers.IndexTLSRouteByGateway,
		} {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TLSRoute{}, indexName, indexerFunc); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
			}
		}
	}

	// Add field indexes for GRPCRoutes
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		indexers.BackendServiceGRPCRouteIndex: indexers.GenerateIndexerGRPCRoutebyBackendService(r.Client, r.logger),
		indexers.GatewayGRPCRouteIndex:        indexers.IndexGRPCRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	// IndexBackendTLSPolicies by referenced ConfigMaps
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.BackendTLSPolicy{}, indexers.BackendTLSPolicyConfigMapIndex, indexers.IndexBTLSPolicyByConfigMap); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", indexers.BackendTLSPolicyConfigMapIndex, err)
	}

	hasMatchingControllerFn := hasMatchingController(context.Background(), r.Client, controllerName, r.logger)
	gatewayBuilder := ctrl.NewControllerManagedBy(mgr).
		// Watch its own resource
		For(&gatewayv1.Gateway{},
			builder.WithPredicates(gatewayOwnedByController(hasMatchingControllerFn))).
		// Watch GatewayClass resources, which are linked to Gateway
		Watches(&gatewayv1.GatewayClass{},
			watchhandlers.EnqueueRequestForOwningGatewayClass(r.Client, *r.logger),
			builder.WithPredicates(gatewayClassOwnedByController(controllerName))).
		// Watch related backend Service for status
		// LB Services are handled by the Owns call later.
		Watches(&corev1.Service{}, watchhandlers.EnqueueRequestForBackendService(r.Client, *r.logger)).
		// Watch HTTPRoute linked to Gateway
		Watches(&gatewayv1.HTTPRoute{}, watchhandlers.EnqueueRequestForOwningHTTPRoute(r.Client, r.logger, controllerName)).
		// Watch GRPCRoute linked to Gateway
		Watches(&gatewayv1.GRPCRoute{}, watchhandlers.EnqueueRequestForOwningGRPCRoute(r.Client, r.logger, controllerName)).
		// Watch related secrets used to configure TLS
		Watches(&corev1.Secret{},
			watchhandlers.EnqueueRequestForTLSSecret(r.Client, r.logger),
			builder.WithPredicates(predicate.NewPredicateFuncs(r.usedInGateway))).
		// Watch related namespace in allowed namespaces
		Watches(&corev1.Namespace{},
			watchhandlers.EnqueueRequestForAllowedNamespace(r.Client, r.logger)).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1.ReferenceGrant{}, watchhandlers.EnqueueRequestForReferenceGrant(r.Client, r.logger)).
		// Watch for changes to BackendTLSPolicy
		Watches(&gatewayv1.BackendTLSPolicy{}, watchhandlers.EnqueueRequestForBackendTLSPolicy(r.Client, r.logger)).
		Watches(&corev1.ConfigMap{}, watchhandlers.EnqueueRequestForBackendTLSPolicyConfigMap(r.Client, r.logger)).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Owns(&corev1.Service{})

	if tlsRouteEnabled {
		// Watch TLSRoute linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1.TLSRoute{}, watchhandlers.EnqueueRequestForOwningTLSRoute(r.Client, r.logger, controllerName))
	}

	if serviceImportEnabled {
		// Watch for changes to Backend Service Imports
		gatewayBuilder = gatewayBuilder.Watches(&mcsapiv1beta1.ServiceImport{}, watchhandlers.EnqueueRequestForBackendServiceImport(r.Client, *r.logger))
	}

	return gatewayBuilder.Complete(r)
}

func gatewayOwnedByController(hasMatchingControllerFn func(object client.Object) bool) predicate.Predicate {
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

func gatewayClassOwnedByController(controllerName string) predicate.Predicate {
	hasMatchingControllerName := matchesControllerName(controllerName)
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

func (r *gatewayReconciler) usedInGateway(obj client.Object) bool {
	return len(helpers.GetGatewaysForSecret(context.Background(), r.Client, obj, r.logger)) > 0
}
