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
	watchhandlers "github.com/cilium/cilium/operator/pkg/gateway-api/watch-handlers"
)

type ReferenceGrantResource struct {
	ResourceType   *gatewayv1.ReferenceGrant
	registryConfig helpers.ResourceConfig
}

func NewReferenceGrantResource(r helpers.ResourceConfig) *ReferenceGrantResource {
	return &ReferenceGrantResource{
		ResourceType:   &gatewayv1.ReferenceGrant{},
		registryConfig: r,
	}
}

// ShouldIndex - ReferenceGrants should never be indexed.
func (rg *ReferenceGrantResource) ShouldIndex() bool {
	return false
}

func (rg *ReferenceGrantResource) GetIndexers(logger *slog.Logger) IndexerFuncMap {
	returnMap := make(IndexerFuncMap)
	return returnMap
}

func (rg *ReferenceGrantResource) GetResource() client.Object {
	return rg.ResourceType
}

// ShouldWatch - ReferenceGrants should always be watched.
func (rg *ReferenceGrantResource) ShouldWatch() bool {
	return true
}

func (rg *ReferenceGrantResource) GetWatchHandlers(c client.Client, logger *slog.Logger, scheme *runtime.Scheme, controllerName string) []handler.EventHandler {
	return []handler.EventHandler{watchhandlers.EnqueueRequestForReferenceGrant(c, logger)}
}

func (rg *ReferenceGrantResource) HasStatusSubresource() bool {
	return true
}
