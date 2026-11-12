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

type TCPRouteResource struct {
	ResourceType   *gatewayv1.TCPRoute
	registryConfig RegistryConfig
}

func NewTCPRouteResource(r RegistryConfig) *TCPRouteResource {
	return &TCPRouteResource{
		ResourceType:   &gatewayv1.TCPRoute{},
		registryConfig: r,
	}
}

// ShouldIndex - TCPRoutes are optional.
func (tcpr *TCPRouteResource) ShouldIndex() bool {
	return tcpr.registryConfig.IncludeTCPRoutes
}

func (tcpr *TCPRouteResource) GetIndexers(c helpers.ClientReader, logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	// First, set up the simple indexers
	returnMap[indexers.GatewayTCPRouteIndex] = indexers.IndexTCPRouteByGateway

	// Next, the complex indexers
	returnMap[indexers.BackendServiceTCPRouteIndex] = indexers.GenerateIndexerTCPRoutebyBackendService(c, logger)

	// Lastly, conditional indexers
	if tcpr.registryConfig.IncludeListenerSets {
		returnMap[indexers.TCPRouteListenerSetIndex] = indexers.IndexTCPRouteByListenerSet
	}
	if tcpr.registryConfig.IncludeServiceImports {
		returnMap[indexers.BackendServiceImportTCPRouteIndex] = indexers.IndexTCPRouteByBackendServiceImport
	}

	return returnMap
}

func (tcpr *TCPRouteResource) GetResource() client.Object {
	return tcpr.ResourceType
}

// ShouldWatch - TCPRoutes are optional.
func (tcpr *TCPRouteResource) ShouldWatch() bool {
	return tcpr.registryConfig.IncludeTCPRoutes
}

func (tcpr *TCPRouteResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	return []handler.EventHandler{watchhandlers.EnqueueRequestForOwningTCPRoute(c, logger, controllerName)}
}
