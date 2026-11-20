// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	gateway_inf_ext "sigs.k8s.io/gateway-api-inference-extension/api/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type InferencePoolResource struct {
	ResourceType   *gateway_inf_ext.InferencePool
	registryConfig helpers.ResourceConfig
}

func NewInferencePoolResource(r helpers.ResourceConfig) *InferencePoolResource {
	return &InferencePoolResource{
		ResourceType:   &gateway_inf_ext.InferencePool{},
		registryConfig: r,
	}
}

// ShouldIndex - InferencePools should always be indexed.
func (ip *InferencePoolResource) ShouldIndex() bool {
	return false
}

func (ip *InferencePoolResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (ip *InferencePoolResource) GetResource() client.Object {
	return ip.ResourceType
}

// ShouldWatch - InferencePools should always be watched.
func (ip *InferencePoolResource) ShouldWatch() bool {
	return true
}

func (ip *InferencePoolResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	return []handler.EventHandler{watchhandlers.EnqueueRequestForOwningInferencePool(c, logger, controllerName)}
}

func (ip *InferencePoolResource) HasStatusSubresource() bool {
	return true
}
