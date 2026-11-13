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

type TLSRouteResource struct {
	ResourceType   *gatewayv1.TLSRoute
	registryConfig helpers.ResourceConfig
}

func NewTLSRouteResource(r helpers.ResourceConfig) *TLSRouteResource {
	return &TLSRouteResource{
		ResourceType:   &gatewayv1.TLSRoute{},
		registryConfig: r,
	}
}

// ShouldIndex - TLSRoutes should always be indexed.
func (tr *TLSRouteResource) ShouldIndex() bool {
	return true
}

func (tr *TLSRouteResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	// First, set up the simple indexers
	returnMap[indexers.GatewayTLSRouteIndex] = indexers.IndexTLSRouteByGateway

	// Next, the complex indexers
	returnMap[indexers.BackendServiceTLSRouteIndex] = indexers.GenerateIndexerTLSRoutebyBackendService(logger, tr.registryConfig)

	// Lastly, conditional indexers
	if tr.registryConfig.IncludeListenerSets {
		returnMap[indexers.TLSRouteListenerSetIndex] = indexers.IndexTLSRouteByListenerSet
	}
	if tr.registryConfig.IncludeServiceImports {
		returnMap[indexers.BackendServiceImportTLSRouteIndex] = indexers.IndexTLSRouteByBackendServiceImport
	}

	return returnMap
}

func (tr *TLSRouteResource) GetResource() client.Object {
	return tr.ResourceType
}

// ShouldWatch - TLSRoutes should always be watched.
func (tr *TLSRouteResource) ShouldWatch() bool {
	return true
}

func (tr *TLSRouteResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	return []handler.EventHandler{watchhandlers.EnqueueRequestForOwningTLSRoute(c, logger, controllerName)}
}

func (tr *TLSRouteResource) HandleStatus() bool {
	return true
}
