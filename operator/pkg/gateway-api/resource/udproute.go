// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type UDPRouteResource struct {
	ResourceType   *gatewayv1.UDPRoute
	registryConfig helpers.ResourceConfig
}

func NewUDPRouteResource(r helpers.ResourceConfig) *UDPRouteResource {
	return &UDPRouteResource{
		ResourceType:   &gatewayv1.UDPRoute{},
		registryConfig: r,
	}
}

// ShouldIndex - UDPRoutes are optional.
func (udpr *UDPRouteResource) ShouldIndex() bool {
	return udpr.registryConfig.IncludeUDPRoutes
}

func (udpr *UDPRouteResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	// First, set up the simple indexers
	returnMap[indexers.GatewayUDPRouteIndex] = indexers.IndexUDPRouteByGateway

	// Next, the complex indexers
	returnMap[indexers.BackendServiceUDPRouteIndex] = indexers.GenerateIndexerUDPRoutebyBackendService(logger, udpr.registryConfig)

	// Lastly, conditional indexers
	if udpr.registryConfig.IncludeListenerSets {
		returnMap[indexers.UDPRouteListenerSetIndex] = indexers.IndexUDPRouteByListenerSet
	}
	if udpr.registryConfig.IncludeServiceImports {
		returnMap[indexers.BackendServiceImportUDPRouteIndex] = indexers.IndexUDPRouteByBackendServiceImport
	}

	return returnMap
}

func (udpr *UDPRouteResource) GetResource() client.Object {
	return udpr.ResourceType
}

// ShouldWatch - UDPRoutes are optional.
func (udpr *UDPRouteResource) ShouldWatch() bool {
	return udpr.registryConfig.IncludeUDPRoutes
}

func (udpr *UDPRouteResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	return []handler.EventHandler{watchhandlers.EnqueueRequestForOwningUDPRoute(c, logger, controllerName)}
}

func (udpr *UDPRouteResource) HandleStatus() bool {
	return true
}
