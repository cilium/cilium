package xds

import (
	"context"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

const (
	adminClusterName      = "/envoy-admin"
	egressClusterName     = "egress-cluster"
	egressTLSClusterName  = "egress-cluster-tls"
	ingressClusterName    = "ingress-cluster"
	ingressTLSClusterName = "ingress-cluster-tls"
	metricsListenerName   = "envoy-prometheus-metrics-listener"
	adminListenerName     = "envoy-admin-listener"
)

// XDSServer provides a high-lever interface to manage resources published using the xDS gRPC API.
type XDSServer interface {
	// AddListener adds a listener to a running Envoy proxy.
	AddListener(ctx context.Context, name string, kind policy.L7ParserType, port uint16, isIngress bool, mayUseOriginalSourceAddr bool, wg *completion.WaitGroup, cb func(err error)) error
	// AddAdminListener adds an Admin API listener to Envoy.
	AddAdminListener(ctx context.Context, port uint16, wg *completion.WaitGroup)
	// AddMetricsListener adds a prometheus metrics listener to Envoy.
	AddMetricsListener(ctx context.Context, port uint16, wg *completion.WaitGroup)
	// RemoveListener removes an existing Envoy Listener.
	RemoveListener(ctx context.Context, name string, wg *completion.WaitGroup) AckingResourceMutatorRevertFunc

	// UpsertEnvoyResources inserts or updates Envoy resources in 'resources' to the xDS cache,
	// from where they will be delivered to Envoy via xDS streaming gRPC.
	UpsertEnvoyResources(ctx context.Context, resources Resources) error
	// UpdateEnvoyResources removes any resources in 'old' that are not
	// present in 'new' and then adds or updates all resources in 'new'.
	// Envoy does not support changing the listening port of an existing
	// listener, so if the port changes we have to delete the old listener
	// and then add the new one with the new port number.
	UpdateEnvoyResources(ctx context.Context, old, new Resources) error
	// DeleteEnvoyResources deletes all Envoy resources in 'resources'.
	DeleteEnvoyResources(ctx context.Context, resources Resources) error

	// GetNetworkPolicies returns the current version of the network policies with the given names.
	// If resourceNames is empty, all resources are returned.
	//
	// Only used for testing
	GetNetworkPolicies(resourceNames []string) (map[string]*cilium.NetworkPolicy, error)
	// UseCurrentNetworkPolicy waits for any pending update on NetworkPolicy to be acked.
	UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup)
	// UpdateNetworkPolicy adds or updates a network policy in the set published to L7 proxies.
	// When the proxy acknowledges the network policy update, it will result in
	// a subsequent call to the endpoint's OnProxyPolicyUpdate() function.
	UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, func() error)
	// RemoveNetworkPolicy removes network policies relevant to the specified
	// endpoint from the set published to L7 proxies, and stops listening for
	// acks for policies on this endpoint.
	RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource)
	// RemoveAllNetworkPolicies removes all network policies from the set published
	// to L7 proxies.
	RemoveAllNetworkPolicies(ctx context.Context)
}

// Resources contains all Envoy resources parsed from a CiliumEnvoyConfig CRD.
// Each resource type is stored in a map keyed by resource name.
type Resources struct {
	Listeners       map[string]*envoy_config_listener.Listener
	Secrets         map[string]*envoy_config_tls.Secret
	Routes          map[string]*envoy_config_route.RouteConfiguration
	Clusters        map[string]*envoy_config_cluster.Cluster
	Endpoints       map[string]*envoy_config_endpoint.ClusterLoadAssignment
	NetworkPolicies map[string]*cilium.NetworkPolicy

	// Callback functions that are called if the corresponding Listener change was successfully acked by Envoy
	PortAllocationCallbacks map[string]func(context.Context) error `json:"-" yaml:"-"`
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
