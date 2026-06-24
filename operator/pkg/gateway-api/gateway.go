// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/predicates"
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
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	logger         *slog.Logger
	controllerName string
}

func newGatewayReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger, controllerName string) *gatewayReconciler {
	scopedLog := logger.With(logfields.Controller, gateway)

	return &gatewayReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		translator:     translator,
		logger:         scopedLog,
		controllerName: controllerName,
	}
}

// SetupWithManager sets up the controller with the Manager.
// The reconciler will be triggered by Gateway, or any cilium-managed GatewayClass events
func (r *gatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Determine which optional CRDs are enabled. The scheme is registered from
	// the autodetected CRDs, so Recognizes() reflects what is installed.
	scheme := r.Client.Scheme()
	tcpRouteEnabled := helpers.HasTCPRouteSupport(scheme)
	udpRouteEnabled := helpers.HasUDPRouteSupport(scheme)
	serviceImportEnabled := helpers.HasServiceImportSupport(scheme)
	listenerSetEnabled := helpers.HasListenerSetSupport(scheme)

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
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, indexers.ImplementationGatewayIndex, indexers.GenerateIndexerGatewayByImplementation(r.Client, gatewayv1.GatewayController(r.controllerName))); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", indexers.ImplementationGatewayIndex, err)
	}

	// Index Gateways by referenced TLS Secrets
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.Gateway{}, helpers.GatewaySecretIndex, indexers.IndexGatewayBySecret); err != nil {
		return fmt.Errorf("failed to setup field indexer %q: %w", helpers.GatewaySecretIndex, err)
	}

	// Add indexes for TLSRoutes
	for indexName, indexerFunc := range map[string]client.IndexerFunc{
		indexers.BackendServiceTLSRouteIndex: indexers.GenerateIndexerTLSRoutebyBackendService(r.Client, r.logger),
		indexers.GatewayTLSRouteIndex:        indexers.IndexTLSRouteByGateway,
	} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TLSRoute{}, indexName, indexerFunc); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
		}
	}

	// Add indexes for TCPRoutes
	if tcpRouteEnabled {
		for indexName, indexerFunc := range map[string]client.IndexerFunc{
			indexers.BackendServiceTCPRouteIndex: indexers.GenerateIndexerTCPRoutebyBackendService(r.Client, r.logger),
			indexers.GatewayTCPRouteIndex:        indexers.IndexTCPRouteByGateway,
		} {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TCPRoute{}, indexName, indexerFunc); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexName, err)
			}
		}
	}

	// Add indexes for UDPRoutes
	if udpRouteEnabled {
		for indexName, indexerFunc := range map[string]client.IndexerFunc{
			indexers.BackendServiceUDPRouteIndex: indexers.GenerateIndexerUDPRoutebyBackendService(r.Client, r.logger),
			indexers.GatewayUDPRouteIndex:        indexers.IndexUDPRouteByGateway,
		} {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.UDPRoute{}, indexName, indexerFunc); err != nil {
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

	// Index ListenerSets by parent Gateway, and routes by ListenerSet parentRefs
	if listenerSetEnabled {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.ListenerSet{}, indexers.ListenerSetGatewayIndex, indexers.IndexListenerSetByGateway); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.ListenerSetGatewayIndex, err)
		}

		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.ListenerSet{}, helpers.ListenerSetSecretIndex, indexers.IndexListenerSetBySecret); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", helpers.ListenerSetSecretIndex, err)
		}

		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.HTTPRoute{}, indexers.HTTPRouteListenerSetIndex, indexers.IndexHTTPRouteByListenerSet); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.HTTPRouteListenerSetIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.GRPCRoute{}, indexers.GRPCRouteListenerSetIndex, indexers.IndexGRPCRouteByListenerSet); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.GRPCRouteListenerSetIndex, err)
		}
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1.TLSRoute{}, indexers.TLSRouteListenerSetIndex, indexers.IndexTLSRouteByListenerSet); err != nil {
			return fmt.Errorf("failed to setup field indexer %q: %w", indexers.TLSRouteListenerSetIndex, err)
		}
		if tcpRouteEnabled {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.TCPRoute{}, indexers.TCPRouteListenerSetIndex, indexers.IndexTCPRouteByListenerSet); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexers.TCPRouteListenerSetIndex, err)
			}
		}
		if udpRouteEnabled {
			if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gatewayv1alpha2.UDPRoute{}, indexers.UDPRouteListenerSetIndex, indexers.IndexUDPRouteByListenerSet); err != nil {
				return fmt.Errorf("failed to setup field indexer %q: %w", indexers.UDPRouteListenerSetIndex, err)
			}
		}
	}

	hasMatchingControllerFn := helpers.GatewayHasMatchingControllerFn(context.Background(), r.Client, r.controllerName, r.logger)
	gatewayBuilder := ctrl.NewControllerManagedBy(mgr).
		// Watch its own resource
		For(&gatewayv1.Gateway{},
			builder.WithPredicates(predicates.GatewayOwnedByController(hasMatchingControllerFn))).
		// Watch GatewayClass resources, which are linked to Gateway
		Watches(&gatewayv1.GatewayClass{},
			watchhandlers.EnqueueRequestForOwningGatewayClass(r.Client, *r.logger),
			builder.WithPredicates(predicates.GatewayClassOwnedByController(r.controllerName))).
		// Watch related backend Service for status
		// LB Services are handled by the Owns call later.
		Watches(&corev1.Service{}, watchhandlers.EnqueueRequestForBackendService(r.Client, *r.logger)).
		// Watch HTTPRoute linked to Gateway
		Watches(&gatewayv1.HTTPRoute{}, watchhandlers.EnqueueRequestForOwningHTTPRoute(r.Client, r.logger, r.controllerName)).
		// Watch GRPCRoute linked to Gateway
		Watches(&gatewayv1.GRPCRoute{}, watchhandlers.EnqueueRequestForOwningGRPCRoute(r.Client, r.logger, r.controllerName)).
		// Watch TLSRoute linked to Gateway
		Watches(&gatewayv1.TLSRoute{}, watchhandlers.EnqueueRequestForOwningTLSRoute(r.Client, r.logger, r.controllerName)).
		// Watch related secrets used to configure TLS
		Watches(&corev1.Secret{},
			watchhandlers.EnqueueRequestForTLSSecret(r.Client, r.controllerName, r.logger),
			builder.WithPredicates(predicate.NewPredicateFuncs(predicates.SecretUsedInGatewayFn(r.Client, r.controllerName, r.logger)))).
		// Watch related namespace in allowed namespaces
		Watches(&corev1.Namespace{},
			watchhandlers.EnqueueRequestForAllowedNamespace(r.Client, r.logger)).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1.ReferenceGrant{}, watchhandlers.EnqueueRequestForReferenceGrant(r.Client, r.logger)).
		// Watch for changes to BackendTLSPolicy
		Watches(&gatewayv1.BackendTLSPolicy{}, watchhandlers.EnqueueRequestForBackendTLSPolicy(r.Client, r.logger)).
		Watches(&corev1.ConfigMap{}, watchhandlers.EnqueueRequestForBackendTLSPolicyConfigMap(r.Client, r.logger)).
		// Watch for changes to node in order to populate gateway ip addresses if svc of type NodePort
		Watches(&corev1.Node{}, watchhandlers.EnqueueRequestForNodes(r.Client, r.logger, owningGatewayLabel)).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Owns(&corev1.Service{}).
		Owns(&discoveryv1.EndpointSlice{})

	if tcpRouteEnabled {
		// Watch TCPRoute linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1alpha2.TCPRoute{}, watchhandlers.EnqueueRequestForOwningTCPRoute(r.Client, r.logger, r.controllerName))
	}

	if udpRouteEnabled {
		// Watch UDPRoute linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1alpha2.UDPRoute{}, watchhandlers.EnqueueRequestForOwningUDPRoute(r.Client, r.logger, r.controllerName))
	}

	if listenerSetEnabled {
		// Watch ListenerSet linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1.ListenerSet{}, watchhandlers.EnqueueRequestForListenerSetOwner(r.Client, r.logger, defaultControllerName))
	}

	if serviceImportEnabled {
		// Watch for changes to Backend Service Imports
		gatewayBuilder = gatewayBuilder.Watches(&mcsapiv1beta1.ServiceImport{}, watchhandlers.EnqueueRequestForBackendServiceImport(r.Client, *r.logger))
	}

	return gatewayBuilder.Complete(r)
}
