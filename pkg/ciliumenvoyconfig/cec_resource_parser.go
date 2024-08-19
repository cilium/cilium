// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/hive/cell"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_endpoint "github.com/cilium/proxy/go/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_config_healthcheck "github.com/cilium/proxy/go/envoy/extensions/filters/http/health_check/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	envoy_config_upstream "github.com/cilium/proxy/go/envoy/extensions/upstreams/http/v3"
	envoy_config_types "github.com/cilium/proxy/go/envoy/type/v3"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/envoy"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
)

const (
	ciliumBPFMetadataListenerFilterName = "cilium.bpf_metadata"
	ciliumNetworkFilterName             = "cilium.network"
	ciliumL7FilterName                  = "cilium.l7policy"
	envoyRouterFilterName               = "envoy.filters.http.router"

	httpProtocolOptionsType = "envoy.extensions.upstreams.http.v3.HttpProtocolOptions"

	upstreamCodecFilterTypeURL   = "type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec"
	quicUpstreamTransportTypeURL = "type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicUpstreamTransport"
	upstreamTlsContextTypeURL    = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext"
	ciliumL7FilterTypeURL        = "type.googleapis.com/cilium.L7Policy"
)

type cecResourceParser struct {
	logger        logrus.FieldLogger
	portAllocator PortAllocator

	ingressIPv4 net.IP
	ingressIPv6 net.IP
}

type parserParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	Proxy          *proxy.Proxy
	LocalNodeStore *node.LocalNodeStore
}

func newCECResourceParser(params parserParams) *cecResourceParser {
	parser := &cecResourceParser{
		logger:        params.Logger,
		portAllocator: params.Proxy,
	}

	// Retrieve Ingress IPs from local Node.
	// It's assumed that these don't change.
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			localNode, err := params.LocalNodeStore.Get(ctx)
			if err != nil {
				return fmt.Errorf("failed to get LocalNodeStore: %w", err)
			}

			parser.ingressIPv4 = localNode.IPv4IngressIP
			parser.ingressIPv6 = localNode.IPv6IngressIP

			params.Logger.
				WithField(logfields.V4IngressIP, localNode.IPv4IngressIP).
				WithField(logfields.V6IngressIP, localNode.IPv6IngressIP).
				Debug("Retrieved Ingress IPs from Node")

			return nil
		},
	})

	return parser
}

type PortAllocator interface {
	AllocateCRDProxyPort(name string) (uint16, error)
	AckProxyPort(ctx context.Context, name string) error
	ReleaseProxyPort(name string) error
}

// parseResources parses all supported Envoy resource types from CiliumEnvoyConfig CRD to the internal type `envoy.Resources`.
//
// - Qualify names by prepending the namespace and name of the origin CEC to the Envoy resource names.
// - Validate resources
// - Inject Cilium specifics into the Listeners (BPF Metadata listener filter, Network filter & L7 filter)
// - Assign a random proxy port to Listeners that don't have an explicit address specified.
//
// Parameters:
//   - `cecNamespace` and `cecName` will be prepended to the Envoy resource names.
//   - `xdsResources` are the resources from the CiliumEnvoyConfig or CiliumClusterwideEnvoyConfig.
//   - `isL7LB` defines whether these resources are used for L7 loadbalancing. If `true`, the Envoy Cilium Network- and L7 filters are always
//     added to all non-internal Listeners. In addition, the info gets passed to the Envoy Cilium BPF Metadata listener filter on all Listeners.
//   - `useOriginalSourceAddr` is passed to the Envoy Cilium BPF Metadata listener filter on all Listeners.
//   - `newResources` is passed as `true` when parsing resources that are being added or are the new version of the resources being updated,
//     and as `false` if the resources are being removed or are the old version of the resources being updated. Only 'new' resources are validated.
func (r *cecResourceParser) parseResources(cecNamespace string, cecName string, xdsResources []cilium_v2.XDSResource, isL7LB bool, useOriginalSourceAddr bool, newResources bool) (envoy.Resources, error) {
	// only validate new  resources - old ones are already applied
	validate := newResources

	// upstream filters are injected if any non-internal listener is L7 LB
	// and downstream filters were injected.
	injectCiliumUpstreamFilters := false

	resources := envoy.Resources{}
	for _, res := range xdsResources {
		// Skip empty TypeURLs, which are left behind when Unmarshaling resource JSON fails
		if res.TypeUrl == "" {
			continue
		}
		message, err := res.UnmarshalNew()
		if err != nil {
			return envoy.Resources{}, err
		}
		typeURL := res.GetTypeUrl()
		switch typeURL {
		case envoy.ListenerTypeURL:
			listener, ok := message.(*envoy_config_listener.Listener)
			if !ok {
				return envoy.Resources{}, fmt.Errorf("invalid type for Listener: %T", message)
			}
			// Check that a listener name is provided
			if listener.Name == "" {
				return envoy.Resources{}, fmt.Errorf("unspecified Listener name")
			}

			if option.Config.EnableBPFTProxy {
				// Envoy since 1.20.0 uses SO_REUSEPORT on listeners by default.
				// BPF TPROXY is currently not compatible with SO_REUSEPORT, so
				// disable it.  Note that this may degrade Envoy performance.
				listener.EnableReusePort = &wrapperspb.BoolValue{Value: false}
			}

			// Only inject Cilium filters if all of the following conditions are fulfilled
			// * Cilium allocates listener address or it's a listener for a L7 loadbalancer
			// * It's not an internal listener
			injectCiliumFilters := (listener.GetAddress() == nil || isL7LB) && listener.GetInternalListener() == nil

			// Fill in SDS & RDS config source if unset
			for _, fc := range listener.FilterChains {
				fillInTransportSocketXDS(cecNamespace, cecName, fc.TransportSocket)
				foundCiliumNetworkFilter := false
				for i, filter := range fc.Filters {
					if filter.Name == ciliumNetworkFilterName {
						foundCiliumNetworkFilter = true
					}
					tc := filter.GetTypedConfig()
					if tc == nil {
						continue
					}
					switch tc.GetTypeUrl() {
					case envoy.HttpConnectionManagerTypeURL:
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
								rds.ConfigSource = envoy.CiliumXDSConfigSource
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

							// Also inject upstream filters for L7 LB when injecting the downstream
							// HTTP enforcement filter
							if isL7LB {
								injectCiliumUpstreamFilters = true
							}
						}

						httpFiltersUpdated := qualifyHttpFilters(cecNamespace, cecName, hcmConfig)
						updated = updated || httpFiltersUpdated

						if updated {
							filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(hcmConfig),
							}
						}
					case envoy.TCPProxyTypeURL:
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
					if injectCiliumFilters && !foundCiliumNetworkFilter {
						// Inject Cilium network filter just before the HTTP Connection Manager or TCPProxy filter
						fc.Filters = append(fc.Filters[:i+1], fc.Filters[i:]...)
						fc.Filters[i] = &envoy_config_listener.Filter{
							Name: ciliumNetworkFilterName,
							ConfigType: &envoy_config_listener.Filter_TypedConfig{
								TypedConfig: toAny(&cilium.NetworkFilter{}),
							},
						}
					}
					break // Done with this filter chain
				}
			}

			name := listener.Name
			listener.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, listener.Name, api.ForceNamespace)

			// Check for duplicate after the name has been qualified
			for i := range resources.Listeners {
				if listener.Name == resources.Listeners[i].Name {
					return envoy.Resources{}, fmt.Errorf("duplicate Listener name %q", listener.Name)
				}
			}

			if validate {
				if err := listener.Validate(); err != nil {
					return envoy.Resources{}, fmt.Errorf("failed to validate Listener (%w): %s", err, listener.String())
				}
			}
			resources.Listeners = append(resources.Listeners, listener)

			r.logger.Debugf("ParseResources: Parsed listener %q: %v", name, listener)

		case envoy.RouteTypeURL:
			route, ok := message.(*envoy_config_route.RouteConfiguration)
			if !ok {
				return envoy.Resources{}, fmt.Errorf("invalid type for Route: %T", message)
			}
			// Check that a Route name is provided
			if route.Name == "" {
				return envoy.Resources{}, fmt.Errorf("unspecified RouteConfiguration name")
			}

			qualifyRouteConfigurationResourceNames(cecNamespace, cecName, route)

			name := route.Name
			route.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name, api.ForceNamespace)

			// Check for duplicate after the name has been qualified
			for i := range resources.Routes {
				if route.Name == resources.Routes[i].Name {
					return envoy.Resources{}, fmt.Errorf("duplicate Route name %q", route.Name)
				}
			}

			if validate {
				if err := route.Validate(); err != nil {
					return envoy.Resources{}, fmt.Errorf("failed to validate RouteConfiguration (%w): %s", err, route.String())
				}
			}
			resources.Routes = append(resources.Routes, route)

			r.logger.Debugf("ParseResources: Parsed route %q: %v", name, route)

		case envoy.ClusterTypeURL:
			cluster, ok := message.(*envoy_config_cluster.Cluster)
			if !ok {
				return envoy.Resources{}, fmt.Errorf("invalid type for Route: %T", message)
			}
			// Check that a Cluster name is provided
			if cluster.Name == "" {
				return envoy.Resources{}, fmt.Errorf("unspecified Cluster name")
			}

			fillInTransportSocketXDS(cecNamespace, cecName, cluster.TransportSocket)

			// Fill in EDS config source if unset
			if enum := cluster.GetType(); enum == envoy_config_cluster.Cluster_EDS {
				if cluster.EdsClusterConfig == nil {
					cluster.EdsClusterConfig = &envoy_config_cluster.Cluster_EdsClusterConfig{}
				}
				if cluster.EdsClusterConfig.EdsConfig == nil {
					cluster.EdsClusterConfig.EdsConfig = envoy.CiliumXDSConfigSource
				}
			}

			if cluster.LoadAssignment != nil {
				qualifyEDSEndpoints(cecNamespace, cecName, cluster.LoadAssignment)
			}

			name := cluster.Name
			cluster.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			// Check for duplicate after the name has been qualified
			for i := range resources.Clusters {
				if cluster.Name == resources.Clusters[i].Name {
					return envoy.Resources{}, fmt.Errorf("duplicate Cluster name %q", cluster.Name)
				}
			}

			if validate {
				if err := cluster.Validate(); err != nil {
					return envoy.Resources{}, fmt.Errorf("failed to validate Cluster %q (%w): %s", cluster.Name, err, cluster.String())
				}
			}
			resources.Clusters = append(resources.Clusters, cluster)

			r.logger.Debugf("ParseResources: Parsed cluster %q: %v", name, cluster)

		case envoy.EndpointTypeURL:
			endpoints, ok := message.(*envoy_config_endpoint.ClusterLoadAssignment)
			if !ok {
				return envoy.Resources{}, fmt.Errorf("invalid type for Route: %T", message)
			}
			// Check that a Cluster name is provided
			if endpoints.ClusterName == "" {
				return envoy.Resources{}, fmt.Errorf("unspecified ClusterLoadAssignment cluster_name")
			}

			name := endpoints.ClusterName
			qualifyEDSEndpoints(cecNamespace, cecName, endpoints)

			// Check for duplicate after the name has been qualified
			for i := range resources.Endpoints {
				if endpoints.ClusterName == resources.Endpoints[i].ClusterName {
					return envoy.Resources{}, fmt.Errorf("duplicate cluster_name %q", endpoints.ClusterName)
				}
			}

			if validate {
				if err := endpoints.Validate(); err != nil {
					return envoy.Resources{}, fmt.Errorf("failed to validate ClusterLoadAssignment for cluster %q (%w): %s", endpoints.ClusterName, err, endpoints.String())
				}
			}
			resources.Endpoints = append(resources.Endpoints, endpoints)

			r.logger.Debugf("ParseResources: Parsed endpoints for cluster %q: %v", name, endpoints)

		case envoy.SecretTypeURL:
			secret, ok := message.(*envoy_config_tls.Secret)
			if !ok {
				return envoy.Resources{}, fmt.Errorf("invalid type for Secret: %T", message)
			}
			// Check that a Secret name is provided
			if secret.Name == "" {
				return envoy.Resources{}, fmt.Errorf("unspecified Secret name")
			}

			name := secret.Name
			secret.Name, _ = api.ResourceQualifiedName(cecNamespace, cecName, name)

			// Check for duplicate after the name has been qualified
			for i := range resources.Secrets {
				if secret.Name == resources.Secrets[i].Name {
					return envoy.Resources{}, fmt.Errorf("duplicate Secret name %q", secret.Name)
				}
			}

			if validate {
				if err := secret.Validate(); err != nil {
					return envoy.Resources{}, fmt.Errorf("failed to validate Secret for cluster %q: %w", secret.Name, err)
				}
			}
			resources.Secrets = append(resources.Secrets, secret)

			r.logger.Debugf("ParseResources: Parsed secret: %s", name)

		default:
			return envoy.Resources{}, fmt.Errorf("unsupported type: %s", typeURL)
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
				port, err := r.portAllocator.AllocateCRDProxyPort(listenerName)
				if err != nil || port == 0 {
					return envoy.Resources{}, fmt.Errorf("listener port allocation for %q failed: %w", listenerName, err)
				}
				if resources.PortAllocationCallbacks == nil {
					resources.PortAllocationCallbacks = make(map[string]func(context.Context) error)
				}
				if newResources {
					resources.PortAllocationCallbacks[listenerName] = func(ctx context.Context) error { return r.portAllocator.AckProxyPort(ctx, listenerName) }
				} else {
					resources.PortAllocationCallbacks[listenerName] = func(_ context.Context) error { return r.portAllocator.ReleaseProxyPort(listenerName) }
				}

				listener.Address, listener.AdditionalAddresses = envoy.GetLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
			}

			// Inject Cilium bpf metadata listener filter, if not already present.
			// This must be done after listener address/port is already set.
			found := false
			for _, lf := range listener.ListenerFilters {
				if lf.Name == ciliumBPFMetadataListenerFilterName {
					found = true
					break
				}
			}
			if !found {
				// Get the listener port from the listener's (main) address
				port := uint16(listener.GetAddress().GetSocketAddress().GetPortValue())

				listener.ListenerFilters = append(listener.ListenerFilters, r.getBPFMetadataListenerFilter(useOriginalSourceAddr, isL7LB, port))
			}
		}

		if validate {
			if err := listener.Validate(); err != nil {
				return envoy.Resources{}, fmt.Errorf("failed to validate Listener %q (%w): %s", listener.Name, err, listener.String())
			}
		}
	}

	// Validate that internal listeners exist
	for _, cluster := range resources.Clusters {
		if cluster.LoadAssignment != nil {
			if err := validateEDSEndpoints(cecNamespace, cecName, cluster.LoadAssignment, resources.Listeners); err != nil {
				return envoy.Resources{}, fmt.Errorf("ParseResources: Cluster refers to missing internal listener %q (%w): %s", cluster.Name, err, cluster.String())
			}
		}
	}
	for _, endpoints := range resources.Endpoints {
		if err := validateEDSEndpoints(cecNamespace, cecName, endpoints, resources.Listeners); err != nil {
			return envoy.Resources{}, fmt.Errorf("ParseResources: Endpoint refers to missing internal listener %q (%w): %s", endpoints.ClusterName, err, endpoints.String())
		}
	}

	if injectCiliumUpstreamFilters {
		for _, cluster := range resources.Clusters {
			opts := &envoy_config_upstream.HttpProtocolOptions{}

			if cluster.TypedExtensionProtocolOptions == nil {
				cluster.TypedExtensionProtocolOptions = make(map[string]*anypb.Any)
			}

			a := cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType]
			if a != nil {
				if err := a.UnmarshalTo(opts); err != nil {
					return envoy.Resources{}, fmt.Errorf("failed to unmarshal HttpProtocolOptions: %w", err)
				}
			}

			// Figure out if upstream supports ALPN so that we can add missing upstream
			// protocol config
			supportsALPN := false
			ts := cluster.GetTransportSocket()
			if ts != nil {
				tc := ts.GetTypedConfig()
				if tc == nil {
					return envoy.Resources{}, fmt.Errorf("Transport socket has no type: %s", ts.String())
				}
				switch tc.GetTypeUrl() {
				case upstreamTlsContextTypeURL, quicUpstreamTransportTypeURL:
					supportsALPN = true
				}
			}
			injected, err := injectCiliumUpstreamL7Filter(opts, supportsALPN)
			if err != nil {
				return envoy.Resources{}, fmt.Errorf("failed to inject upstream filters for cluster %q: %w", cluster.Name, err)
			}
			if injected {
				cluster.TypedExtensionProtocolOptions[httpProtocolOptionsType] = toAny(opts)
				if validate {
					if err := cluster.Validate(); err != nil {
						return envoy.Resources{}, fmt.Errorf("failed to validate Cluster %q after injecting Cilium upstream filters (%s): %w", cluster.Name, cluster.String(), err)
					}
				}
			}
		}
	}

	return resources, nil
}

// 'l7lb' triggers the upstream mark to embed source pod EndpointID instead of source security ID
func (r *cecResourceParser) getBPFMetadataListenerFilter(useOriginalSourceAddr bool, l7lb bool, proxyPort uint16) *envoy_config_listener.ListenerFilter {
	conf := &cilium.BpfMetadata{
		IsIngress:                false,
		UseOriginalSourceAddress: useOriginalSourceAddr,
		BpfRoot:                  bpf.BPFFSRoot(),
		IsL7Lb:                   l7lb,
		ProxyId:                  uint32(proxyPort),
	}

	// Set Ingress source addresses if configuring for L7 LB.  One of these will be used when
	// useOriginalSourceAddr is false, or when the source is known to not be from the local node
	// (in such a case use of the original source address would lead to broken routing for the
	// return traffic, as it would not be sent to the this node where upstream connection
	// originates from).
	//
	// Note: This means that all non-local traffic will be identified by the destination to be
	// coming from/via "Ingress", even if the listener is not an Ingress listener.
	// We could refrain from using these ingress addresses in such cases, but then the upstream
	// traffic would come from an (other) host IP, which is even worse.
	//
	// One solution to this dilemma would be to never configure these addresses if
	// useOriginalSourceAddr is true and let such traffic fail.
	if l7lb {
		if r.ingressIPv4 != nil {
			conf.Ipv4SourceAddress = r.ingressIPv4.String()
			// Enforce ingress policy for Ingress
			conf.EnforcePolicyOnL7Lb = true
		}
		if r.ingressIPv6 != nil {
			conf.Ipv6SourceAddress = r.ingressIPv6.String()
			// Enforce ingress policy for Ingress
			conf.EnforcePolicyOnL7Lb = true
		}
		r.logger.Debugf("%s: ipv4_source_address: %s", ciliumBPFMetadataListenerFilterName, conf.GetIpv4SourceAddress())
		r.logger.Debugf("%s: ipv6_source_address: %s", ciliumBPFMetadataListenerFilterName, conf.GetIpv6SourceAddress())
	}

	return &envoy_config_listener.ListenerFilter{
		Name: ciliumBPFMetadataListenerFilterName,
		ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
			TypedConfig: toAny(conf),
		},
	}
}

// qualifyAddress finds if there is a ServerListenerName in the address and qualifies it
func qualifyAddress(namespace, name string, address *envoy_config_core.Address) {
	internalAddress := address.GetEnvoyInternalAddress()
	if internalAddress != nil {
		if x, ok := internalAddress.GetAddressNameSpecifier().(*envoy_config_core.EnvoyInternalAddress_ServerListenerName); ok && x.ServerListenerName != "" {
			x.ServerListenerName, _ = api.ResourceQualifiedName(namespace, name, x.ServerListenerName)
		}
	}
}

// qualifyEDSEndpoints qualifies resource names in a ClusterLoadAssignment (aka EDS endpoint)
func qualifyEDSEndpoints(namespace, name string, eds *envoy_config_endpoint.ClusterLoadAssignment) {
	eds.ClusterName, _ = api.ResourceQualifiedName(namespace, name, eds.ClusterName)

	for _, cla := range eds.Endpoints {
		for _, lbe := range cla.LbEndpoints {
			endpoint := lbe.GetEndpoint()
			if endpoint != nil {
				qualifyAddress(namespace, name, endpoint.Address)
			}
			for i := range endpoint.AdditionalAddresses {
				qualifyAddress(namespace, name, endpoint.AdditionalAddresses[i].Address)
			}
		}
	}
}

// validateAddress checks that the referred to internal listener is specified, if it is in the same CRD
func validateAddress(namespace, name string, address *envoy_config_core.Address,
	listeners []*envoy_config_listener.Listener,
) error {
	internalAddress := address.GetEnvoyInternalAddress()
	if internalAddress != nil {
		if x, ok := internalAddress.GetAddressNameSpecifier().(*envoy_config_core.EnvoyInternalAddress_ServerListenerName); ok && x.ServerListenerName != "" {

			internalNamespace, internalName, listenerName := api.ParseQualifiedName(x.ServerListenerName)
			if internalNamespace == namespace && internalName == name {
				found := false
				// Check that the listener exists and is an internal listener
				for i := range listeners {
					if x.ServerListenerName == listeners[i].Name &&
						listeners[i].GetInternalListener() != nil {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("missing internal listener: %s", listenerName)
				}
			}
		}
	}
	return nil
}

// validateEDSEndpoints checks internal listener references, if any
func validateEDSEndpoints(namespace, name string, eds *envoy_config_endpoint.ClusterLoadAssignment,
	listeners []*envoy_config_listener.Listener,
) error {
	for _, cla := range eds.Endpoints {
		for _, lbe := range cla.LbEndpoints {
			endpoint := lbe.GetEndpoint()
			if endpoint != nil {
				err := validateAddress(namespace, name, endpoint.Address, listeners)
				if err != nil {
					return err
				}
			}
			for i := range endpoint.AdditionalAddresses {
				err := validateAddress(namespace, name, endpoint.AdditionalAddresses[i].Address, listeners)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
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

// injectCiliumL7Filter injects the Cilium HTTP filter just before the HTTP Router filter
func injectCiliumL7Filter(hcmConfig *envoy_config_http.HttpConnectionManager) bool {
	foundCiliumL7Filter := false

	for j, httpFilter := range hcmConfig.HttpFilters {
		switch httpFilter.Name {
		case ciliumL7FilterName:
			foundCiliumL7Filter = true
		case envoyRouterFilterName:
			if !foundCiliumL7Filter {
				hcmConfig.HttpFilters = append(hcmConfig.HttpFilters[:j+1], hcmConfig.HttpFilters[j:]...)
				hcmConfig.HttpFilters[j] = envoy.GetCiliumHttpFilter()
				return true
			}
		}
	}

	return false
}

func qualifyHttpFilters(cecNamespace string, cecName string, hcmConfig *envoy_config_http.HttpConnectionManager) bool {
	updated := false

	for _, httpFilter := range hcmConfig.HttpFilters {
		switch h := httpFilter.ConfigType.(type) {
		case *envoy_config_http.HttpFilter_TypedConfig:
			any, err := h.TypedConfig.UnmarshalNew()
			if err != nil {
				continue
			}

			switch httpFilterConfig := any.(type) {
			case *envoy_config_healthcheck.HealthCheck:
				clusters := map[string]*envoy_config_types.Percent{}
				for c, p := range httpFilterConfig.ClusterMinHealthyPercentages {
					clusterName := c
					updatedClusterName, nameUpdated := api.ResourceQualifiedName(cecNamespace, cecName, c)
					if nameUpdated {
						updated = true
						clusterName = updatedClusterName
					}

					clusters[clusterName] = p
				}

				if updated {
					httpFilterConfig.ClusterMinHealthyPercentages = clusters
					h.TypedConfig = toAny(httpFilterConfig)
				}
			}
		}
	}

	return updated
}

// injectCiliumUpstreamL7Filter injects the Cilium HTTP filter just before the Upstream Codec filter
func injectCiliumUpstreamL7Filter(opts *envoy_config_upstream.HttpProtocolOptions, supportsALPN bool) (bool, error) {
	filters := opts.GetHttpFilters()
	if filters == nil {
		filters = make([]*envoy_config_http.HttpFilter, 0, 2)
	}

	foundCiliumL7Filter := false
	codecFilterIndex := -1
	for j, filter := range filters {
		// no filters allowed after upstream codec filter
		if codecFilterIndex >= 0 {
			return false, fmt.Errorf("filter after codec filter: %s", filter.String())
		}
		if len(filter.Name) == 0 {
			return false, fmt.Errorf("filter has no name: %s", filter.String())
		}
		tc := filter.GetTypedConfig()
		if tc == nil {
			return false, fmt.Errorf("filter has no type: %s", filter.String())
		}
		switch tc.GetTypeUrl() {
		case ciliumL7FilterTypeURL:
			foundCiliumL7Filter = true
		case upstreamCodecFilterTypeURL:
			codecFilterIndex = j
		}
	}
	changed := false
	if !foundCiliumL7Filter {
		j := codecFilterIndex
		if j >= 0 {
			filters = append(filters[:j+1], filters[j:]...)
			filters[j] = envoy.GetCiliumHttpFilter()
		} else {
			filters = append(filters, envoy.GetCiliumHttpFilter())
		}
		changed = true
	}

	// Add CodecFilter if missing
	if codecFilterIndex < 0 {
		filters = append(filters, envoy.GetUpstreamCodecFilter())
		changed = true
	}

	if changed {
		opts.HttpFilters = filters
	}

	// Add required HttpProtocolOptions fields
	if opts.GetUpstreamProtocolOptions() == nil {
		if supportsALPN {
			// Use auto config for upstream transports that support ALPN
			opts.UpstreamProtocolOptions = &envoy_config_upstream.HttpProtocolOptions_AutoConfig{
				AutoConfig: &envoy_config_upstream.HttpProtocolOptions_AutoHttpConfig{},
			}
		} else {
			// Use downstream protocol for upstream transports that do not support ALPN
			opts.UpstreamProtocolOptions = &envoy_config_upstream.HttpProtocolOptions_UseDownstreamProtocolConfig{
				UseDownstreamProtocolConfig: &envoy_config_upstream.HttpProtocolOptions_UseDownstreamHttpConfig{
					Http2ProtocolOptions: &envoy_config_core.Http2ProtocolOptions{},
				},
			}
		}
		changed = true
	}

	if err := opts.Validate(); err != nil {
		return false, fmt.Errorf("failed to validate HttpProtocolOptions after injecting Cilium upstream filters (%s): %w", opts.String(), err)
	}

	return changed, nil
}

func fillInTlsContextXDS(cecNamespace string, cecName string, tls *envoy_config_tls.CommonTlsContext) (updated bool) {
	qualify := func(sc *envoy_config_tls.SdsSecretConfig) {
		if sc.SdsConfig == nil {
			sc.SdsConfig = envoy.CiliumXDSConfigSource
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
		if cvc := tls.GetCombinedValidationContext(); cvc != nil {
			if sc := cvc.GetValidationContextSdsSecretConfig(); sc != nil {
				qualify(sc)
			}
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

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
