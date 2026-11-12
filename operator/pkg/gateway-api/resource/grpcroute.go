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

type GRPCRouteResource struct {
	ResourceType   *gatewayv1.GRPCRoute
	registryConfig RegistryConfig
}

func NewGRPCRouteResource(r RegistryConfig) *GRPCRouteResource {
	return &GRPCRouteResource{
		ResourceType:   &gatewayv1.GRPCRoute{},
		registryConfig: r,
	}
}

// ShouldIndex - GRPCRoutes should always be indexed.
func (grpcr *GRPCRouteResource) ShouldIndex() bool {
	return true
}

func (grpcr *GRPCRouteResource) GetIndexers(c helpers.ClientReader, logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	// First, set up the simple indexers
	returnMap[indexers.GatewayGRPCRouteIndex] = indexers.IndexGRPCRouteByGateway

	// Next, the complex indexers
	returnMap[indexers.BackendServiceGRPCRouteIndex] = indexers.GenerateIndexerGRPCRoutebyBackendService(c, logger)

	// Lastly, conditional indexers
	if grpcr.registryConfig.IncludeListenerSets {
		returnMap[indexers.GRPCRouteListenerSetIndex] = indexers.IndexGRPCRouteByListenerSet
	}
	if grpcr.registryConfig.IncludeServiceImports {
		returnMap[indexers.BackendServiceImportGRPCRouteIndex] = indexers.IndexGRPCRouteByBackendServiceImport
	}

	return returnMap
}

func (grpcr *GRPCRouteResource) GetResource() client.Object {
	return grpcr.ResourceType
}

// ShouldWatch - GRPCRoutes should always be watched.
func (grpcr *GRPCRouteResource) ShouldWatch() bool {
	return true
}

func (grpcr *GRPCRouteResource) GetWatchHandler(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) handler.TypedEventHandler[client.Object, reconcile.Request] {
	return watchhandlers.EnqueueRequestForOwningGRPCRoute(c, logger, controllerName)
}
