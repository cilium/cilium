// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	mcsapiv1beta1 "sigs.k8s.io/mcs-api/pkg/apis/v1beta1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/loading"
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

	hostNetworkTCPUDPRouteUnsupportedReason = "Gateway API Host Network mode is enabled"
)

// gatewayReconciler reconciles a Gateway object
type gatewayReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	translator translation.Translator

	inputLoader             *loading.TranslationInputLoader
	routeStatusManager      *RouteStatusManager
	logger                  *slog.Logger
	controllerName          string
	tcpUDPRouteSupport      bool
	tcpUDPUnsupportedReason string
	hostNetworkEnabled      bool
	hostNetworkLabel        metav1.LabelSelector
}

func newGatewayReconciler(mgr ctrl.Manager, translator translation.Translator, logger *slog.Logger, controllerName string, hostNetworkEnabled bool, hostNetworkLabel metav1.LabelSelector) *gatewayReconciler {
	scopedLog := logger.With(logfields.Controller, gateway)
	includeTCPRoutes := helpers.HasTCPRouteSupport(mgr.GetScheme())
	includeUDPRoutes := helpers.HasUDPRouteSupport(mgr.GetScheme())
	tcpUDPRouteSupport := !hostNetworkEnabled

	return &gatewayReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		translator: translator,
		inputLoader: loading.NewTranslationInputLoader(mgr.GetClient(), scopedLog, controllerName, loading.TranslationInputLoaderConfig{
			IncludeTCPRoutes:      includeTCPRoutes,
			IncludeUDPRoutes:      includeUDPRoutes,
			IncludeServiceImports: helpers.HasServiceImportSupport(mgr.GetScheme()),
			IncludeListenerSets:   helpers.HasListenerSetSupport(mgr.GetScheme()),
		}),
		routeStatusManager: NewRouteStatusManager(
			mgr.GetClient(),
			scopedLog,
			controllerName,
			RouteStatusManagerConfig{
				IncludeTCPRoutes:        includeTCPRoutes,
				IncludeUDPRoutes:        includeUDPRoutes,
				TCPUDPRouteSupport:      tcpUDPRouteSupport,
				TCPUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
			},
		),
		logger:                  scopedLog,
		controllerName:          controllerName,
		tcpUDPRouteSupport:      tcpUDPRouteSupport,
		tcpUDPUnsupportedReason: hostNetworkTCPUDPRouteUnsupportedReason,
		hostNetworkEnabled:      hostNetworkEnabled,
		hostNetworkLabel:        hostNetworkLabel,
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

	if err := r.inputLoader.SetupIndexes(mgr); err != nil {
		return err
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
		Watches(&corev1.Service{}, watchhandlers.EnqueueRequestForBackendService(r.Client, r.Scheme, *r.logger, r.controllerName)).
		// Watch HTTPRoute linked to Gateway
		Watches(&gatewayv1.HTTPRoute{}, watchhandlers.EnqueueRequestForOwningHTTPRoute(r.Client, r.logger, r.controllerName)).
		// Watch GRPCRoute linked to Gateway
		Watches(&gatewayv1.GRPCRoute{}, watchhandlers.EnqueueRequestForOwningGRPCRoute(r.Client, r.logger, r.controllerName)).
		// Watch TLSRoute linked to Gateway
		Watches(&gatewayv1.TLSRoute{}, watchhandlers.EnqueueRequestForOwningTLSRoute(r.Client, r.logger, r.controllerName)).
		// Watch related secrets used to configure TLS
		Watches(&corev1.Secret{},
			watchhandlers.EnqueueRequestForTLSSecret(r.Client, r.controllerName, r.logger)).
		// Watch related namespace in allowed namespaces
		Watches(&corev1.Namespace{},
			watchhandlers.EnqueueRequestForAllowedNamespace(r.Client, r.logger)).
		// Watch for changes to Reference Grants
		Watches(&gatewayv1.ReferenceGrant{}, watchhandlers.EnqueueRequestForReferenceGrant(r.Client, r.logger)).
		// Watch for changes to BackendTLSPolicy
		Watches(&gatewayv1.BackendTLSPolicy{}, watchhandlers.EnqueueRequestForBackendTLSPolicy(r.Client, r.logger, r.controllerName)).
		Watches(&corev1.ConfigMap{}, watchhandlers.EnqueueRequestForBackendTLSPolicyConfigMap(r.Client, r.logger, r.controllerName)).
		// Watch for changes to node in order to populate gateway ip addresses if svc of type NodePort
		Watches(&corev1.Node{}, watchhandlers.EnqueueRequestForNodes(r.Client, r.logger, owningGatewayLabel, r.controllerName)).
		// Watch created and owned resources
		Owns(&ciliumv2.CiliumEnvoyConfig{}).
		Owns(&corev1.Service{}).
		Owns(&discoveryv1.EndpointSlice{})

	if tcpRouteEnabled {
		// Watch TCPRoute linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1.TCPRoute{}, watchhandlers.EnqueueRequestForOwningTCPRoute(r.Client, r.logger, r.controllerName))
	}

	if udpRouteEnabled {
		// Watch UDPRoute linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1.UDPRoute{}, watchhandlers.EnqueueRequestForOwningUDPRoute(r.Client, r.logger, r.controllerName))
	}

	if listenerSetEnabled {
		// Watch ListenerSet linked to Gateway
		gatewayBuilder = gatewayBuilder.Watches(&gatewayv1.ListenerSet{}, watchhandlers.EnqueueRequestForListenerSetOwner(r.Client, r.logger, r.controllerName))
	}

	if serviceImportEnabled {
		// Watch for changes to Backend Service Imports
		gatewayBuilder = gatewayBuilder.Watches(&mcsapiv1beta1.ServiceImport{}, watchhandlers.EnqueueRequestForBackendServiceImport(r.Client, *r.logger, r.controllerName))
	}

	return gatewayBuilder.Complete(r)
}
