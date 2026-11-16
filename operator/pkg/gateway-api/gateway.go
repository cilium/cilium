// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/loading"
	"github.com/cilium/cilium/operator/pkg/gateway-api/predicates"
	"github.com/cilium/cilium/operator/pkg/gateway-api/resource"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// Deprecated: owningGatewayLabel will be removed later in favour of gatewayNameLabel
	owningGatewayLabel = "io.cilium.gateway/owning-gateway"
	gatewayNameLabel   = "gateway.networking.k8s.io/gateway-name"

	lastTransitionTime = "LastTransitionTime"

	hostNetworkTCPUDPRouteUnsupportedReason = "Gateway API Host Network mode is enabled"
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client     client.Client
	scheme     *runtime.Scheme
	translator translation.Translator

	inputLoader                         *loading.TranslationInputLoader
	gatewayStatusManager                *GatewayStatusManager
	listenerStatusManager               *ListenerStatusManager
	routeStatusManager                  *RouteStatusManager
	backendTLSPolicyStatusManager       *BackendTLSPolicyStatusManager
	inferencePoolStatusManager          *InferencePoolStatusManager
	logger                              *slog.Logger
	controllerName                      string
	gatewayAPIInferenceExtensionEnabled bool
	resourceRegistry                    resource.Registry
}

func newGatewayReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger, controllerName string, hostNetworkEnabled bool, hostNetworkLabel metav1.LabelSelector, gatewayAPIInferenceExtensionEnabled bool) *gatewayReconciler {
	scopedLog := logger.With(logfields.Controller, gateway)

	resourceConfig := helpers.ResourceConfig{
		IncludeTCPRoutes:        helpers.HasTCPRouteSupport(mgr.GetScheme()),
		IncludeUDPRoutes:        helpers.HasUDPRouteSupport(mgr.GetScheme()),
		IncludeServiceImports:   helpers.HasServiceImportSupport(mgr.GetScheme()),
		IncludeListenerSets:     helpers.HasListenerSetSupport(mgr.GetScheme()),
		IncludeInferencePools:   helpers.HasInferencePoolSupport(mgr.GetScheme()),
		TCPRouteUDPRouteSupport: !hostNetworkEnabled,
		TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
		OwningGatewayLabel:      owningGatewayLabel,
	}

	return &gatewayReconciler{
		client:               mgr.GetClient(),
		scheme:               mgr.GetScheme(),
		translator:           translator,
		inputLoader:          loading.NewTranslationInputLoader(mgr.GetClient(), scopedLog, controllerName, resourceConfig),
		gatewayStatusManager: NewGatewayStatusManager(mgr.GetClient(), scopedLog, hostNetworkLabel),
		listenerStatusManager: NewListenerStatusManager(
			mgr.GetClient(),
			scopedLog,
			resourceConfig,
		),
		routeStatusManager: NewRouteStatusManager(
			mgr.GetClient(),
			scopedLog,
			controllerName,
			resourceConfig,
			nil,
		),
		backendTLSPolicyStatusManager:       NewBackendTLSPolicyStatusManager(mgr.GetClient(), controllerName),
		inferencePoolStatusManager:          NewInferencePoolStatusManager(mgr.GetClient(), controllerName),
		logger:                              scopedLog,
		controllerName:                      controllerName,
		gatewayAPIInferenceExtensionEnabled: gatewayAPIInferenceExtensionEnabled,
		resourceRegistry:                    resource.NewGatewayRegistry(resourceConfig),
	}
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Add Indexes for managed resources.
	// Note that ordering is apparently important here, this must happen before the controller setup begins.
	for _, resource := range r.resourceRegistry.GetResources() {
		if resource.ShouldIndex() {
			for indexName, indexer := range resource.GetIndexers(r.logger) {
				if err := mgr.GetFieldIndexer().IndexField(context.Background(), resource.GetResource(), indexName, indexer); err != nil {
					return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
				}
			}
		}
	}

	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(context.Background(), r.client, r.controllerName, r.logger)
	gatewayBuilder := ctrl.NewControllerManagedBy(mgr).
		// Watch its own resource
		For(&gatewayv1.Gateway{},
			builder.WithPredicates(predicates.GatewayOwnedByController(hasMatchingControllerFn))).
		// Watch GatewayClass resources, which are linked to Gateway
		Watches(&gatewayv1.GatewayClass{},
			watchhandlers.EnqueueRequestForOwningGatewayClass(r.client, *r.logger),
			builder.WithPredicates(predicates.GatewayClassOwnedByController(r.controllerName))).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		// This handles Services _owned_ by the reconciler, or in other words, LB Services.
		Owns(&corev1.Service{}).
		Owns(&discoveryv1.EndpointSlice{})

	// Gateways don't fit in the current Resource Registry
	// TODO(youngnick): Decide if we will change things to make them fit.
	// Note that this _must_ happen after controller setup begins.
	gatewayIndexFuncs := resource.IndexerFuncMap{
		indexers.ImplementationGatewayIndex: indexers.GenerateIndexerGatewayByImplementation(r.client, gatewayv1.GatewayController(r.controllerName)),
		helpers.GatewaySecretIndex:          indexers.IndexGatewayBySecret,
	}
	for indexName, indexFunc := range gatewayIndexFuncs {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, indexName, indexFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	// For all non-Gateway resources, add Watches per the Resource.
	for _, resource := range r.resourceRegistry.GetResources() {
		if resource.ShouldWatch() {
			for _, handler := range resource.GetWatchHandlers(r.client, r.logger, r.scheme, r.controllerName) {
				gatewayBuilder.Watches(resource.GetResource(), handler)
			}
		}
	}
	return gatewayBuilder.Complete(r)
}
