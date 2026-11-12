// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type HTTPRouteResource struct {
	ResourceType   *gatewayv1.HTTPRoute
	registryConfig RegistryConfig
}

func NewHTTPRouteResource(r RegistryConfig) *HTTPRouteResource {
	return &HTTPRouteResource{
		ResourceType:   &gatewayv1.HTTPRoute{},
		registryConfig: r,
	}
}

// ShouldIndex - HTTPRoutes should always be indexed.
func (hr *HTTPRouteResource) ShouldIndex() bool {
	return true
}

func (hr *HTTPRouteResource) GetIndexers(c helpers.ClientReader, logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	// First, set up the simple indexers
	returnMap[indexers.GatewayHTTPRouteIndex] = indexers.IndexHTTPRouteByGateway

	// Next, the complex indexers
	returnMap[indexers.BackendServiceHTTPRouteIndex] = indexers.GenerateIndexerHTTPRouteByBackendService(c, logger)

	// Lastly, conditional indexers
	if hr.registryConfig.IncludeListenerSets {
		returnMap[indexers.HTTPRouteListenerSetIndex] = indexers.IndexHTTPRouteByListenerSet
	}
	if hr.registryConfig.IncludeServiceImports {
		returnMap[indexers.BackendServiceImportHTTPRouteIndex] = indexers.IndexHTTPRouteByBackendServiceImport
	}

	if hr.registryConfig.IncludeInferencePools {
		returnMap[indexers.InferencePoolHTTPRouteIndex] = indexers.GenerateIndexerHTTPRouteByInferencePool
	}
	return returnMap
}

func (hr *HTTPRouteResource) GetResource() client.Object {
	return hr.ResourceType
}

// ShouldWatch - HTTPRoutes should always be watched.
func (hr *HTTPRouteResource) ShouldWatch() bool {
	return true
}

func (hr *HTTPRouteResource) GetWatchHandler(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) handler.TypedEventHandler[client.Object, reconcile.Request] {
	return watchhandlers.EnqueueRequestForOwningHTTPRoute(c, logger, controllerName)
}
