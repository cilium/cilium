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

type ListenerSetResource struct {
	ResourceType   *gatewayv1.ListenerSet
	registryConfig RegistryConfig
}

func NewListenerSetResource(r RegistryConfig) *ListenerSetResource {
	return &ListenerSetResource{
		ResourceType:   &gatewayv1.ListenerSet{},
		registryConfig: r,
	}
}

// ShouldIndex - ListenerSets are optional.
func (lsr *ListenerSetResource) ShouldIndex() bool {
	return lsr.registryConfig.IncludeListenerSets
}

func (lsr *ListenerSetResource) GetIndexers(c helpers.ClientReader, logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)

	if lsr.registryConfig.IncludeListenerSets {
		// First, set up the simple indexers
		returnMap[indexers.ListenerSetGatewayIndex] = indexers.IndexListenerSetByGateway
		returnMap[helpers.ListenerSetSecretIndex] = indexers.IndexListenerSetBySecret
	}

	return returnMap
}

func (lsr *ListenerSetResource) GetResource() client.Object {
	return lsr.ResourceType
}

// ShouldWatch - ListenerSets are optional.
func (lsr *ListenerSetResource) ShouldWatch() bool {
	return lsr.registryConfig.IncludeListenerSets
}

func (lsr *ListenerSetResource) GetWatchHandler(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) handler.TypedEventHandler[client.Object, reconcile.Request] {
	return watchhandlers.EnqueueRequestForListenerSetOwner(c, logger, controllerName)
}
