// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"maps"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
)

// XDSServer provides a high-level interface to manage resources published using the xDS gRPC API.
type XDSServer interface {
	// AddListener adds a listener to Envoy, configured for the given L7 parser type.
	// The listener is created on the given port and direction (ingress/egress).
	// If mayUseOriginalSourceAddr is true, the listener may use the original source address
	// for upstream connections.
	// The completion is signaled on 'wg' and 'cb' is called with any error from Envoy ACK/NACK.
	AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error

	// AddAdminListener adds an Envoy admin API listener on the given port.
	// The completion is signaled on 'wg'.
	AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup)

	// AddMetricsListener adds a Prometheus metrics listener to Envoy on the given port.
	// The completion is signaled on 'wg'.
	AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup)

	// RemoveListener removes an existing Envoy listener by name.
	// The completion is signaled on 'wg'. Returns a revert function that can be called
	// to undo the removal.
	RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) AckingResourceMutatorRevertFunc

	// UpsertEnvoyResources inserts or updates Envoy resources (listeners, routes, clusters,
	// endpoints, secrets) in the xDS cache, from where they will be delivered to Envoy via
	// xDS streaming gRPC. The completion is signaled on 'wg'.
	UpsertEnvoyResources(ctx context.Context, resources Resources, wg *completion.WaitGroup) error
	// UpdateEnvoyResources removes any resources in 'old' that are not present in 'new' and
	// then adds or updates all resources in 'new'. Envoy does not support changing the listening
	// port of an existing listener, so if the port changes we have to delete the old listener
	// and then add the new one with the new port number. The completion is signaled on 'wg'.
	UpdateEnvoyResources(ctx context.Context, old, new Resources, wg *completion.WaitGroup) error
	// DeleteEnvoyResources deletes the given Envoy resources from the xDS cache.
	// If resources includes listeners the caller MUST pass a context with a timeout to prevent
	// indefinite blocking in case Envoy never responds with an ACK/NACK.
	DeleteEnvoyResources(ctx context.Context, resources Resources, wg *completion.WaitGroup) error
	// UpdateNetworkPolicy adds or updates a network policy in the set published to L7 proxies.
	// When the proxy acknowledges the network policy update, it will result in
	// a subsequent call to the endpoint's OnProxyPolicyUpdate() function.
	UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.RevertFunc, revert.FinalizeFunc)
	// RemoveNetworkPolicy removes network policies relevant to the specified
	// endpoint from the set published to L7 proxies, and stops listening for
	// acks for policies on this endpoint.
	RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource)

	// RemoveAllNetworkPolicies removes all network policies from the set published to L7 proxies.
	RemoveAllNetworkPolicies()
}

// Resources contains all Envoy resources parsed from a CiliumEnvoyConfig CRD.
// Each resource type is stored in a map keyed by resource name.
type Resources struct {
	Listeners          map[string]*envoy_config_listener.Listener
	Secrets            map[string]*envoy_config_tls.Secret
	Routes             map[string]*envoy_config_route.RouteConfiguration
	Clusters           map[string]*envoy_config_cluster.Cluster
	Endpoints          map[string]*envoy_config_endpoint.ClusterLoadAssignment
	NetworkPolicies    map[string]*cilium.NetworkPolicy
	NetworkPolicyHosts map[string]*cilium.NetworkPolicyHosts

	// Callback functions that are called if the corresponding Listener change was successfully acked by Envoy
	PortAllocationCallbacks map[string]func(context.Context) error `json:"-" yaml:"-"`
}

// NewResources returns a Resources with all maps initialized.
func NewResources() Resources {
	return Resources{
		Listeners:               make(map[string]*envoy_config_listener.Listener),
		Secrets:                 make(map[string]*envoy_config_tls.Secret),
		Routes:                  make(map[string]*envoy_config_route.RouteConfiguration),
		Clusters:                make(map[string]*envoy_config_cluster.Cluster),
		Endpoints:               make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		NetworkPolicies:         make(map[string]*cilium.NetworkPolicy),
		NetworkPolicyHosts:      make(map[string]*cilium.NetworkPolicyHosts),
		PortAllocationCallbacks: make(map[string]func(context.Context) error),
	}
}

// DeepCopy returns a copy of the Resources with cloned maps.
// Protobuf values are shared (not deep-copied) since they are treated as immutable once published.
func cloneOrInit[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return make(map[K]V)
	}
	return maps.Clone(m)
}

func (r *Resources) DeepCopy() *Resources {
	if r == nil {
		return nil
	}
	return &Resources{
		Listeners:               cloneOrInit(r.Listeners),
		Secrets:                 cloneOrInit(r.Secrets),
		Routes:                  cloneOrInit(r.Routes),
		Clusters:                cloneOrInit(r.Clusters),
		Endpoints:               cloneOrInit(r.Endpoints),
		NetworkPolicies:         cloneOrInit(r.NetworkPolicies),
		NetworkPolicyHosts:      cloneOrInit(r.NetworkPolicyHosts),
		PortAllocationCallbacks: cloneOrInit(r.PortAllocationCallbacks),
	}
}

// ListenersAddedOrDeleted returns 'true' if a listener is added or removed when updating from 'old'
// to 'new'.
// TODO(nezdolik): clean this up once full ADS switch is done.
func (old *Resources) ListenersAddedOrDeleted(new *Resources) bool {
	// Typically the number of listeners in a CEC is small (e.g, one), so it should be OK to
	// scan the slices like here
	for _, nl := range new.Listeners {
		found := false
		for _, ol := range old.Listeners {
			if ol.Name == nl.Name {
				found = true
				break
			}
		}
		if !found {
			return true // a listener was added
		}
	}
	for _, ol := range old.Listeners {
		found := false
		for _, nl := range new.Listeners {
			if nl.Name == ol.Name {
				found = true
				break
			}
		}
		if !found {
			return true // a listener was removed
		}
	}
	return false
}
