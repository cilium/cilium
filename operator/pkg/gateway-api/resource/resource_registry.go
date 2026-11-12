// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"log/slog"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

// IndexerFuncMap allows iterating over all the required indexers, and adding them
// individually. The indexer add call requires the indexer name (the key) and an indexer
// func, the value.
type IndexerFuncMap map[string]client.IndexerFunc

type Indexable interface {
	ShouldIndex() bool
	GetIndexers(helpers.ClientReader, *slog.Logger) IndexerFuncMap
}

type Watchable interface {
	ShouldWatch() bool
	GetWatchHandlers(client.Client, *slog.Logger, *runtime.Scheme, string) []handler.EventHandler
}

type Resource interface {
	// GetResource gets the concrete type as a client.Object, which is required
	// by many controller-runtime things.
	GetResource() client.Object
	Indexable
	Watchable
}

type Registry interface {
	AddResource(Resource)
	GetResources() []Resource
}

// RegistryConfig stores what optional functionality is available.
// Sometimes Resources need to know if they or an interaction of
// theirs with another feature is enabled.
type RegistryConfig struct {
	IncludeTCPRoutes      bool
	IncludeUDPRoutes      bool
	IncludeServiceImports bool
	IncludeListenerSets   bool
	IncludeInferencePools bool
}

type GatewayRegistry struct {
	resources      []Resource
	registryConfig RegistryConfig
}

// NewGatewayRegistry creates a new registry for Gateway API Resources.
// Note that it's expected that this registry will only contain Resources
// that are either required, or optional and available.
//
// So, addition of Resources must be gated by if the resource is present
// in the cluster. Use the registryConfig to determine this.
func NewGatewayRegistry(r RegistryConfig) *GatewayRegistry {
	gr := &GatewayRegistry{
		registryConfig: r,
	}

	gr.AddResource(NewHTTPRouteResource(gr.registryConfig))
	gr.AddResource(NewGRPCRouteResource(gr.registryConfig))
	gr.AddResource(NewTLSRouteResource(gr.registryConfig))
	gr.AddResource(NewBackendTLSPolicyResource(gr.registryConfig))
	gr.AddResource(NewConfigMapResource(gr.registryConfig))

	if r.IncludeListenerSets {
		gr.AddResource(NewListenerSetResource(gr.registryConfig))
	}

	if r.IncludeTCPRoutes {
		gr.AddResource(NewTCPRouteResource(gr.registryConfig))
	}

	if r.IncludeUDPRoutes {
		gr.AddResource(NewUDPRouteResource(gr.registryConfig))
	}

	return gr
}

func (gr *GatewayRegistry) AddResource(r Resource) {
	gr.resources = append(gr.resources, r)
}

func (gr *GatewayRegistry) GetResources() []Resource {
	return gr.resources
}
