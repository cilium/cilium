// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type EndpointSliceResource struct {
	ResourceType   *discoveryv1.EndpointSlice
	registryConfig helpers.ResourceConfig
}

func NewEndpointSliceResource(r helpers.ResourceConfig) *EndpointSliceResource {
	return &EndpointSliceResource{
		ResourceType:   &discoveryv1.EndpointSlice{},
		registryConfig: r,
	}
}

// ShouldIndex - EndpointSlices should never be indexed.
func (es *EndpointSliceResource) ShouldIndex() bool {
	return false
}

// GetIndexers Returns an empty map so the nil is typed correctly.
// Should never be called because ShouldIndex is false.
func (es *EndpointSliceResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (es *EndpointSliceResource) GetResource() client.Object {
	return es.ResourceType
}

// ShouldWatch - EndpointSlices should be watched only when InferencePool is enabled.
// InferencePool requires some processing of EndpointSlices to be able to implement it
// correctly.
func (es *EndpointSliceResource) ShouldWatch() bool {
	return es.registryConfig.IncludeInferencePools
}

func (es *EndpointSliceResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	handlers := []handler.EventHandler{}

	if es.registryConfig.IncludeInferencePools {
		handlers = append(handlers, watchhandlers.EnqueueRequestForOwningEndpointSlice(c, logger, controllerName))
	}

	return handlers
}

func (es *EndpointSliceResource) HasStatusSubresource() bool {
	return false
}
