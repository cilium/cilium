// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"fmt"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

type PortAllocator interface {
	AllocateProxyPort(name string, ingress, localOnly bool) (uint16, error)
	AckProxyPort(ctx context.Context, name string) error
	ReleaseProxyPort(name string) error
}

func qualifyTcpProxyResourceNames(namespace, name string, tcpProxy *envoy_config_tcp.TcpProxy) (updated bool) {
	switch c := tcpProxy.GetClusterSpecifier().(type) {
	case *envoy_config_tcp.TcpProxy_Cluster:
		if c != nil {
			c.Cluster, updated = api.ResourceQualifiedName(namespace, name, c.Cluster)
		}
	case *envoy_config_tcp.TcpProxy_WeightedClusters:
		if c != nil {
			for _, wc := range c.WeightedClusters.Clusters {
				var nameUpdated bool
				wc.Name, nameUpdated = api.ResourceQualifiedName(namespace, name, wc.Name)
				if nameUpdated {
					updated = true
				}
			}
		}
	}
	return updated
}

func qualifyRouteConfigurationResourceNames(namespace, name string, routeConfig *envoy_config_route.RouteConfiguration) (updated bool) {
	// Strictly not a reference, and may be an empty string
	routeConfig.Name, updated = api.ResourceQualifiedName(namespace, name, routeConfig.Name, api.ForceNamespace)

	for _, vhost := range routeConfig.VirtualHosts {
		var nameUpdated bool
		vhost.Name, nameUpdated = api.ResourceQualifiedName(namespace, name, vhost.Name, api.ForceNamespace)
		if nameUpdated {
			updated = true
		}
		for _, rt := range vhost.Routes {
			if action := rt.GetRoute(); action != nil {
				if clusterName := action.GetCluster(); clusterName != "" {
					action.GetClusterSpecifier().(*envoy_config_route.RouteAction_Cluster).Cluster, nameUpdated = api.ResourceQualifiedName(namespace, name, clusterName)
					if nameUpdated {
						updated = true
					}
				}
				for _, r := range action.GetRequestMirrorPolicies() {
					if clusterName := r.GetCluster(); clusterName != "" {
						r.Cluster, nameUpdated = api.ResourceQualifiedName(namespace, name, clusterName)
						if nameUpdated {
							updated = true
						}
					}
				}
				if weightedClusters := action.GetWeightedClusters(); weightedClusters != nil {
					for _, cluster := range weightedClusters.GetClusters() {
						cluster.Name, nameUpdated = api.ResourceQualifiedName(namespace, name, cluster.Name)
						if nameUpdated {
							updated = true
						}
					}
				}
			}
		}
	}
	return updated
}

// ParseResources parses all supported Envoy resource types from CiliumEnvoyConfig CRD to Resources
// type cecNamespace and cecName parameters, if not empty, will be prepended to the Envoy resource
// names.
// Parameter `newResources` is passed as `true` when parsing resources that are being added or are the new version of the resources being updated,
// and as `false` if the resources are being removed or are the old version of the resources being updated.
func ParseResources(cecNamespace string, cecName string, anySlice []cilium_v2.XDSResource, validate bool, portAllocator PortAllocator, isL7LB bool, useOriginalSourceAddr bool, newResources bool) (Resources, error) {
	resources := Resources{}
	for _, r := range anySlice {
		// Skip empty TypeURLs, which are left behind when Unmarshaling resource JSON fails
		if r.TypeUrl == "" {
			continue
		}
		message, err := r.UnmarshalNew()
		if err != nil {
			return Resources{}, err
		}
		typeURL := r.GetTypeUrl()
		switch typeURL {
		case ListenerTypeURL:
			listener, ok := message.(*envoy_config_listener.Listener)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Listener: %T", message)
			}
			// Check that a listener name is provided and that it is unique within this CEC
			if listener.Name == "" {
				return Resources{}, fmt.Errorf("'Listener name not provided")
			}
			for i := range resources.Listeners {
				if listener.Name == resources.Listeners[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Listener name %q", listener.Name)
				}
			}

			if option.Config.EnableBPFTProxy {
				// Envoy since 1.20.0 uses SO_REUSEPORT on listeners by default.
				// BPF TPROXY is currently not compatible with SO_REUSEPORT, so
				// disable it.  Note that this may degrade Envoy performance.
				listener.EnableReusePort = &wrapperspb.BoolValue{Value: false}
			}

			// Figure out if this is an internal listener
			isInternalListener := listener.GetInternalListener() != nil

			// Only inject Cilium filters if Cilium allocates listener address
			injectCiliumFilters := listener.GetAddress() == nil && !isInternalListener

			// Fill in SDS & RDS config source if unset
			for _, fc := range listener.FilterChains {
				fillInTransportSocketXDS(cecNamespace, cecName, fc.TransportSocket)
				foundCiliumNetworkFilter := false
				for i, filter := range fc.Filters {
					if filter.Name == "cilium.network" {
						foundCiliumNetworkFilter = true
					}
					tc := filter.GetTypedConfig()
					if tc == nil {
						continue
					}
					switch tc.GetTypeUrl() {
					case HttpConnectionManagerTypeURL:
						any, err := tc.UnmarshalNew()
						if err != nil {
							continue
						}
						hcmConfig, ok := any.(*envoy_config_http.HttpConnectionManager)
						if !ok {
							continue
						}
						updated := false
						if rds := hcmConfig.GetRds(); rds != nil {
							// Since we are prepending CEC namespace and name to Routes name,
							// we must do the same here to point to the correct Route resource.
							if rds.RouteConfigName != "" {
								rds.RouteConfigName, updated = api.ResourceQualifiedName(cecNamespace, cecName, rds.RouteConfigName, api.ForceNamespace)
							}
							if rds.ConfigSource == nil {
								rds.ConfigSource = ciliumXDS
								updated = true
							}
						}
						if routeConfig := hcmConfig.GetRouteConfig(); routeConfig != nil {
							if qualifyRouteConfigurationResourceNames(cecNamespace, cecName, routeConfig) {
								updated = true
							}
						}
						if injectCiliumFilters {
							l7FilterUpdated := injectCiliumL7Filter(hcmConfig)
							updated = updated || l7FilterUpdated
						}
						if updated {
							filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(hcmConfig),
							}
						}
					case TCPProxyTypeURL:
						any, err := tc.UnmarshalNew()
						if err != nil {
							continue
						}
						tcpProxy, ok := any.(*envoy_config_tcp.TcpProxy)
						if !ok {
							continue
						}

						if qualifyTcpProxyResourceNames(cecNamespace, cecName, tcpProxy) {
							filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(tcpProxy),
							}
						}
					default:
						continue
					}
					if injectCiliumFilters {
						if !foundCiliumNetworkFilter {
							// Inject Cilium network filter just before the HTTP Connection Manager or TCPProxy filter
							fc.Filters = append(fc.Filters[:i+1], fc.Filters[i:]...)
							fc.Filters[i] = &envoy_config_listener.Filter{
								Name: "cilium.network",
								ConfigType: &envoy_config_listener.Filter_TypedConfig{
									TypedConfig: toAny(&cilium.NetworkFilter{}),
								},
							}
						}
					}
					break // Done with this filter chain
				}
			}

			name := listener.Name
			listener.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, listener.Name, api.ForceNamespace)

			if validate {
				if err := listener.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate Listener (%s): %s", err, listener.String())
				}
			}
			resources.Listeners = append(resources.Listeners, listener)

			log.Debugf("ParseResources: Parsed listener %q: %v", name, listener)

		case RouteTypeURL:
			route, ok := message.(*envoy_config_route.RouteConfiguration)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Check that a Route name is provided and that it is unique within this CEC
			if route.Name == "" {
				return Resources{}, fmt.Errorf("RouteConfiguration name not provided")
			}
			for i := range resources.Routes {
				if route.Name == resources.Routes[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Route name %q", route.Name)
				}
			}

			qualifyRouteConfigurationResourceNames(cecNamespace, cecName, route)

			name := route.Name
			route.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name, api.ForceNamespace)

			if validate {
				if err := route.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate RouteConfiguration (%s): %s", err, route.String())
				}
			}
			resources.Routes = append(resources.Routes, route)

			log.Debugf("ParseResources: Parsed route %q: %v", name, route)

		case ClusterTypeURL:
			cluster, ok := message.(*envoy_config_cluster.Cluster)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Check that a Cluster name is provided and that it is unique within this CEC
			if cluster.Name == "" {
				return Resources{}, fmt.Errorf("Cluster name not provided")
			}
			for i := range resources.Clusters {
				if cluster.Name == resources.Clusters[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Cluster name %q", cluster.Name)
				}
			}

			fillInTransportSocketXDS(cecNamespace, cecName, cluster.TransportSocket)

			// Fill in EDS config source if unset
			if enum := cluster.GetType(); enum == envoy_config_cluster.Cluster_EDS {
				if cluster.EdsClusterConfig == nil {
					cluster.EdsClusterConfig = &envoy_config_cluster.Cluster_EdsClusterConfig{}
				}
				if cluster.EdsClusterConfig.EdsConfig == nil {
					cluster.EdsClusterConfig.EdsConfig = ciliumXDS
				}
			}

			if cluster.LoadAssignment != nil {
				cluster.LoadAssignment.ClusterName, _ = api.ResourceQualifiedName(cecNamespace, cecName, cluster.LoadAssignment.ClusterName)
			}

			name := cluster.Name
			cluster.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			if validate {
				if err := cluster.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate Cluster %q (%s): %s", cluster.Name, err, cluster.String())
				}
			}
			resources.Clusters = append(resources.Clusters, cluster)

			log.Debugf("ParseResources: Parsed cluster %q: %v", name, cluster)

		case EndpointTypeURL:
			endpoints, ok := message.(*envoy_config_endpoint.ClusterLoadAssignment)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Route: %T", message)
			}
			// Check that a Cluster name is provided and that it is unique within this CEC
			if endpoints.ClusterName == "" {
				return Resources{}, fmt.Errorf("ClusterLoadAssignment cluster_name not provided")
			}
			for i := range resources.Endpoints {
				if endpoints.ClusterName == resources.Endpoints[i].ClusterName {
					return Resources{}, fmt.Errorf("Duplicate cluster_name %q", endpoints.ClusterName)
				}
			}

			name := endpoints.ClusterName
			endpoints.ClusterName, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			if validate {
				if err := endpoints.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate ClusterLoadAssignment for cluster %q (%s): %s", endpoints.ClusterName, err, endpoints.String())
				}
			}
			resources.Endpoints = append(resources.Endpoints, endpoints)

			log.Debugf("ParseResources: Parsed endpoints for cluster %q: %v", name, endpoints)

		case SecretTypeURL:
			secret, ok := message.(*envoy_config_tls.Secret)
			if !ok {
				return Resources{}, fmt.Errorf("Invalid type for Secret: %T", message)
			}
			// Check that a Secret name is provided and that it is unique within this CEC
			if secret.Name == "" {
				return Resources{}, fmt.Errorf("Secret name not provided")
			}
			for i := range resources.Secrets {
				if secret.Name == resources.Secrets[i].Name {
					return Resources{}, fmt.Errorf("Duplicate Secret name %q", secret.Name)
				}
			}

			name := secret.Name
			secret.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			if validate {
				if err := secret.Validate(); err != nil {
					return Resources{}, fmt.Errorf("ParseResources: Could not validate Secret for cluster %q (%s)", secret.Name, err)
				}
			}
			resources.Secrets = append(resources.Secrets, secret)

			log.Debugf("ParseResources: Parsed secret: %s", name)

		default:
			return Resources{}, fmt.Errorf("Unsupported type: %s", typeURL)
		}
	}

	// Allocate TPROXY ports for listeners without address.
	// Do this only after all other possible error cases.
	for _, listener := range resources.Listeners {
		// Figure out if this is an internal listener
		isInternalListener := listener.GetInternalListener() != nil

		if !isInternalListener {
			if listener.GetAddress() == nil {
				listenerName := listener.Name
				port, err := portAllocator.AllocateProxyPort(listenerName, false, true)
				if err != nil || port == 0 {
					return Resources{}, fmt.Errorf("listener port allocation for %q failed: %s", listenerName, err)
				}
				if resources.portAllocationCallbacks == nil {
					resources.portAllocationCallbacks = make(map[string]func(context.Context) error)
				}
				if newResources {
					resources.portAllocationCallbacks[listenerName] = func(ctx context.Context) error { return portAllocator.AckProxyPort(ctx, listenerName) }
				} else {
					resources.portAllocationCallbacks[listenerName] = func(_ context.Context) error { return portAllocator.ReleaseProxyPort(listenerName) }
				}

				listener.Address, listener.AdditionalAddresses = getLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
			}

			// Inject Cilium bpf metadata listener filter, if not already present.
			// This must be done after listener address/port is already set.
			found := false
			for _, lf := range listener.ListenerFilters {
				if lf.Name == "cilium.bpf_metadata" {
					found = true
					break
				}
			}
			if !found {
				// Get the listener port from the listener's (main) address
				port := uint16(listener.GetAddress().GetSocketAddress().GetPortValue())

				listener.ListenerFilters = append(listener.ListenerFilters, getListenerFilter(false /* egress */, useOriginalSourceAddr, isL7LB, port))
			}
		}

		if validate {
			if err := listener.Validate(); err != nil {
				return Resources{}, fmt.Errorf("ParseResources: Could not validate Listener %q (%s): %s", listener.Name, err, listener.String())
			}
		}
	}

	return resources, nil
}

// injectCiliumL7Filter injects the Cilium HTTP filter just before the HTTP Router filter
func injectCiliumL7Filter(hcmConfig *envoy_config_http.HttpConnectionManager) bool {
	foundCiliumL7Filter := false

	for j, httpFilter := range hcmConfig.HttpFilters {
		switch httpFilter.Name {
		case "cilium.l7policy":
			foundCiliumL7Filter = true
		case "envoy.filters.http.router":
			if !foundCiliumL7Filter {
				hcmConfig.HttpFilters = append(hcmConfig.HttpFilters[:j+1], hcmConfig.HttpFilters[j:]...)
				hcmConfig.HttpFilters[j] = getCiliumHttpFilter()
				return true
			}
		}
	}

	return false
}

func fillInTlsContextXDS(cecNamespace string, cecName string, tls *envoy_config_tls.CommonTlsContext) (updated bool) {
	qualify := func(sc *envoy_config_tls.SdsSecretConfig) {
		if sc.SdsConfig == nil {
			sc.SdsConfig = ciliumXDS
			updated = true
		}
		var nameUpdated bool
		sc.Name, nameUpdated = api.ResourceQualifiedName(cecNamespace, cecName, sc.Name)
		if nameUpdated {
			updated = true
		}
	}

	if tls != nil {
		for _, sc := range tls.TlsCertificateSdsSecretConfigs {
			qualify(sc)
		}
		if sc := tls.GetValidationContextSdsSecretConfig(); sc != nil {
			qualify(sc)
		}
	}
	return updated
}

func fillInTransportSocketXDS(cecNamespace string, cecName string, ts *envoy_config_core.TransportSocket) {
	if ts != nil {
		if tc := ts.GetTypedConfig(); tc != nil {
			any, err := tc.UnmarshalNew()
			if err != nil {
				return
			}
			var updated *anypb.Any
			switch tls := any.(type) {
			case *envoy_config_tls.DownstreamTlsContext:
				if fillInTlsContextXDS(cecNamespace, cecName, tls.CommonTlsContext) {
					updated = toAny(tls)
				}
			case *envoy_config_tls.UpstreamTlsContext:
				if fillInTlsContextXDS(cecNamespace, cecName, tls.CommonTlsContext) {
					updated = toAny(tls)
				}
			}
			if updated != nil {
				ts.ConfigType = &envoy_config_core.TransportSocket_TypedConfig{
					TypedConfig: updated,
				}
			}
		}
	}
}
