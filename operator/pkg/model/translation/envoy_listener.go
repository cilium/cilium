// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	"maps"
	goslices "slices"
	"syscall"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_listener_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_extensions_transport_sockets_quic_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/quic/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/slices"
)

const (
	defaultTCPKeepAlive                       = 1 // enabled
	defaultTCPKeepAliveIdleTimeInSeconds      = 10
	defaultTCPKeepAliveProbeIntervalInSeconds = 5
	defaultTCPKeepAliveMaxFailures            = 10
)

const (
	httpConnectionManagerType = "envoy.filters.network.http_connection_manager"
	tcpProxyType              = "envoy.filters.network.tcp_proxy"
	tlsInspectorType          = "envoy.filters.listener.tls_inspector"
	proxyProtocolType         = "envoy.filters.listener.proxy_protocol"
	tlsTransportSocketType    = "envoy.transport_sockets.tls"
	quicTransportSocketType   = "envoy.transport_sockets.quic"

	rawBufferTransportProtocol = "raw_buffer"
	tlsTransportProtocol       = "tls"

	listenerName = "listener"
)

type ListenerMutator func(*envoy_config_listener.Listener) *envoy_config_listener.Listener

func withProxyProtocol() ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		proxyListener := &envoy_config_listener.ListenerFilter{
			Name: proxyProtocolType,
			ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
				TypedConfig: toAny(&envoy_extensions_listener_proxy_protocol_v3.ProxyProtocol{}),
			},
		}
		listener.ListenerFilters = append([]*envoy_config_listener.ListenerFilter{proxyListener}, listener.ListenerFilters...)
		return listener
	}
}

func withAlpn() ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		for _, filterChain := range listener.FilterChains {
			transportSocket := filterChain.GetTransportSocket()
			if transportSocket == nil {
				continue
			}

			downstreamContext := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{}
			err := proto.Unmarshal(transportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downstreamContext)
			if err != nil {
				continue
			}

			// Use `h2,http/1.1` to support both HTTP/2 and HTTP/1.1
			downstreamContext.CommonTlsContext.AlpnProtocols = []string{"h2,http/1.1"}

			transportSocket.ConfigType = &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: toAny(downstreamContext),
			}
		}
		return listener
	}
}

func withXffNumTrustedHops(xff uint32) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		if xff == 0 {
			return listener
		}
		for _, filterChain := range listener.FilterChains {
			for _, filter := range filterChain.Filters {
				if filter.Name == httpConnectionManagerType {
					tc := filter.GetTypedConfig()
					switch tc.GetTypeUrl() {
					case envoy.HttpConnectionManagerTypeURL:
						hcm, err := tc.UnmarshalNew()
						if err != nil {
							continue
						}
						hcmConfig, ok := hcm.(*httpConnectionManagerv3.HttpConnectionManager)
						if !ok {
							continue
						}
						hcmConfig.XffNumTrustedHops = xff
						filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: toAny(hcmConfig),
						}
					}
				}
			}
		}
		return listener
	}
}

func WithStreamIdleTimeout(streamIdleTimeoutSeconds int) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		if streamIdleTimeoutSeconds == 0 {
			return listener
		}
		for _, filterChain := range listener.FilterChains {
			for _, filter := range filterChain.Filters {
				if filter.Name == httpConnectionManagerType {
					tc := filter.GetTypedConfig()
					switch tc.GetTypeUrl() {
					case envoy.HttpConnectionManagerTypeURL:
						hcm, err := tc.UnmarshalNew()
						if err != nil {
							continue
						}
						hcmConfig, ok := hcm.(*httpConnectionManagerv3.HttpConnectionManager)
						if !ok {
							continue
						}
						hcmConfig.StreamIdleTimeout = &durationpb.Duration{
							Seconds: int64(streamIdleTimeoutSeconds),
						}
						filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: toAny(hcmConfig),
						}
					}
				}
			}
		}
		return listener
	}
}

func withHostNetworkPort(m *model.Model, ipv4Enabled bool, ipv6Enabled bool) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		listener.Address, listener.AdditionalAddresses = getHostNetworkListenerAddresses(m.AllPorts(), ipv4Enabled, ipv6Enabled)
		return listener
	}
}

func withSocketOption(tcpKeepAlive, tcpKeepIdleInSeconds, tcpKeepAliveProbeIntervalInSeconds, tcpKeepAliveMaxFailures int64) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		listener.SocketOptions = []*envoy_config_core_v3.SocketOption{
			{
				Description: "Enable TCP keep-alive (default to enabled)",
				Level:       syscall.SOL_SOCKET,
				Name:        syscall.SO_KEEPALIVE,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepAlive,
				},
				State: envoy_config_core_v3.SocketOption_STATE_PREBIND,
			},
			{
				Description: "TCP keep-alive idle time (in seconds) (defaults to 10s)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPIDLE,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepIdleInSeconds,
				},
				State: envoy_config_core_v3.SocketOption_STATE_PREBIND,
			},
			{
				Description: "TCP keep-alive probe intervals (in seconds) (defaults to 5s)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPINTVL,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepAliveProbeIntervalInSeconds,
				},
				State: envoy_config_core_v3.SocketOption_STATE_PREBIND,
			},
			{
				Description: "TCP keep-alive probe max failures.",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPCNT,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepAliveMaxFailures,
				},
				State: envoy_config_core_v3.SocketOption_STATE_PREBIND,
			},
		}
		return listener
	}
}

// desiredEnvoyListener returns the desired Envoy listener for the given model.
func (i *cecTranslator) desiredEnvoyListener(m *model.Model) ([]ciliumv2.XDSResource, error) {
	if m.IsEmpty() {
		return nil, nil
	}

	filterChains, err := i.filterChains(listenerName, m)
	if err != nil {
		return nil, err
	}

	listener := &envoy_config_listener.Listener{
		Name:         listenerName,
		FilterChains: filterChains,
		ListenerFilters: []*envoy_config_listener.ListenerFilter{
			{
				Name: tlsInspectorType,
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
					TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
				},
			},
		},
	}

	for _, fn := range i.listenerMutators(m) {
		listener = fn(listener)
	}

	res, err := toXdsResource(listener, envoy.ListenerTypeURL)
	if err != nil {
		return nil, err
	}
	resources := []ciliumv2.XDSResource{res}

	// Create UDP listener for HTTP/3 QUIC if enabled in config
	if i.Config.HTTP3Enabled {
		for _, httpsPort := range m.HTTPSPorts() {
			udpListener, err := i.desiredQuicListener(m, httpsPort)
			if err != nil {
				return nil, err
			}
			if udpListener != nil {
				udpRes, err := toXdsResource(udpListener, envoy.ListenerTypeURL)
				if err != nil {
					return nil, err
				}
				resources = append(resources, udpRes)
			}
		}
	}

	return resources, nil
}

func (i *cecTranslator) filterChains(name string, m *model.Model) ([]*envoy_config_listener.FilterChain, error) {
	var filterChains []*envoy_config_listener.FilterChain

	if m.IsHTTPListenerConfigured() {
		httpFilterChain, err := i.httpFilterChain(name)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, httpFilterChain)
	}

	if m.IsHTTPSListenerConfigured() {
		httpsFilterChains, err := i.httpsFilterChains(name, m)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, httpsFilterChains...)
	}

	if m.IsTLSPassthroughListenerConfigured() {
		tlsPTFilterChains := tlsPassthroughFilterChains(m)
		filterChains = append(filterChains, tlsPTFilterChains...)
	}

	return filterChains, nil
}

// listenerMutators returns a list of listener mutators to apply to the listener.
func (i *cecTranslator) listenerMutators(m *model.Model) []ListenerMutator {
	res := []ListenerMutator{
		withSocketOption(
			defaultTCPKeepAlive,
			defaultTCPKeepAliveIdleTimeInSeconds,
			defaultTCPKeepAliveProbeIntervalInSeconds,
			defaultTCPKeepAliveMaxFailures),
	}
	if i.Config.ListenerConfig.UseProxyProtocol {
		res = append(res, withProxyProtocol())
	}

	if i.Config.ListenerConfig.UseAlpn {
		res = append(res, withAlpn())
	}

	if i.Config.HostNetworkConfig.Enabled {
		res = append(res, withHostNetworkPort(m, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled))
	}

	if i.Config.ListenerConfig.StreamIdleTimeoutSeconds > 0 {
		res = append(res, WithStreamIdleTimeout(i.Config.ListenerConfig.StreamIdleTimeoutSeconds))
	}

	if i.Config.OriginalIPDetectionConfig.XFFNumTrustedHops > 0 {
		res = append(res, withXffNumTrustedHops(i.Config.OriginalIPDetectionConfig.XFFNumTrustedHops))
	}
	return res
}

func (i *cecTranslator) httpFilterChain(name string) (*envoy_config_listener.FilterChain, error) {
	insecureHttpConnectionManagerName := fmt.Sprintf("%s-insecure", name)
	insecureHttpConnectionManager, err := i.desiredHTTPConnectionManager(
		insecureHttpConnectionManagerName,
		insecureHttpConnectionManagerName,
	)
	if err != nil {
		return nil, err
	}

	return &envoy_config_listener.FilterChain{
		FilterChainMatch: &envoy_config_listener.FilterChainMatch{TransportProtocol: rawBufferTransportProtocol},
		Filters: []*envoy_config_listener.Filter{
			{
				Name: httpConnectionManagerType,
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: insecureHttpConnectionManager.Any,
				},
			},
		},
	}, nil
}

func (i *cecTranslator) httpsFilterChains(name string, m *model.Model) ([]*envoy_config_listener.FilterChain, error) {
	tlsToHostnames := m.TLSSecretsToHostnames()
	if len(tlsToHostnames) == 0 {
		return nil, nil
	}

	var filterChains []*envoy_config_listener.FilterChain

	orderedSecrets := goslices.SortedStableFunc(maps.Keys(tlsToHostnames), func(a, b model.TLSSecret) int {
		return cmp.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})

	for _, secret := range orderedSecrets {
		hostNames := tlsToHostnames[secret]

		secureHttpConnectionManagerName := fmt.Sprintf("%s-secure", name)
		secureHttpConnectionManager, err := i.desiredHTTPConnectionManager(secureHttpConnectionManagerName, secureHttpConnectionManagerName)
		if err != nil {
			return nil, err
		}
		transportSocket, err := toTransportSocket(i.Config.SecretsNamespace, []model.TLSSecret{secret})
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, &envoy_config_listener.FilterChain{
			FilterChainMatch: toFilterChainMatch(hostNames),
			Filters: []*envoy_config_listener.Filter{
				{
					Name: httpConnectionManagerType,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: secureHttpConnectionManager.Any,
					},
				},
			},
			TransportSocket: transportSocket,
		})
	}

	return filterChains, nil
}

// getListenerAddresses creates listener addresses for the given ports, protocol and IP configuration.
// It returns the primary address and additional addresses for dual-stack support.
func getListenerAddresses(ports []uint32, protocol envoy_config_core_v3.SocketAddress_Protocol, ipv4Enabled, ipv6Enabled bool) (*envoy_config_core_v3.Address, []*envoy_config_listener.AdditionalAddress) {
	if len(ports) == 0 {
		return nil, nil
	}

	// Build list of bind addresses based on IP configuration
	var bindAddresses []string
	if ipv4Enabled {
		bindAddresses = append(bindAddresses, "0.0.0.0")
	}
	if ipv6Enabled {
		bindAddresses = append(bindAddresses, "::")
	}
	// Fallback to IPv4 if neither is enabled
	if len(bindAddresses) == 0 {
		bindAddresses = append(bindAddresses, "0.0.0.0")
	}

	// Generate all address combinations
	var addresses []*envoy_config_core_v3.Address_SocketAddress
	for _, p := range ports {
		for _, a := range bindAddresses {
			addresses = append(addresses, &envoy_config_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_config_core_v3.SocketAddress{
					Protocol:      protocol,
					Address:       a,
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: p},
				},
			})
		}
	}

	// First address is primary, rest are additional
	var additionalAddresses []*envoy_config_listener.AdditionalAddress
	if len(addresses) > 1 {
		for _, a := range addresses[1:] {
			additionalAddresses = append(additionalAddresses, &envoy_config_listener.AdditionalAddress{
				Address: &envoy_config_core_v3.Address{
					Address: a,
				},
			})
		}
	}

	return &envoy_config_core_v3.Address{
		Address: addresses[0],
	}, additionalAddresses
}

func getHostNetworkListenerAddresses(ports []uint32, ipv4Enabled, ipv6Enabled bool) (*envoy_config_core_v3.Address, []*envoy_config_listener.AdditionalAddress) {
	if !ipv4Enabled && !ipv6Enabled {
		return nil, nil
	}
	return getListenerAddresses(ports, envoy_config_core_v3.SocketAddress_TCP, ipv4Enabled, ipv6Enabled)
}

func tlsPassthroughFilterChains(m *model.Model) []*envoy_config_listener.FilterChain {
	ptBackendsToHostnames := m.TLSBackendsToHostnames()
	if len(ptBackendsToHostnames) == 0 {
		return nil
	}

	var filterChains []*envoy_config_listener.FilterChain

	orderedBackends := goslices.Sorted(maps.Keys(ptBackendsToHostnames))

	for _, backend := range orderedBackends {
		hostNames := ptBackendsToHostnames[backend]
		filterChains = append(filterChains, &envoy_config_listener.FilterChain{
			FilterChainMatch: toFilterChainMatch(hostNames),
			Filters: []*envoy_config_listener.Filter{
				{
					Name: tcpProxyType,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: toAny(&envoy_extensions_filters_network_tcp_v3.TcpProxy{
							StatPrefix: backend,
							ClusterSpecifier: &envoy_extensions_filters_network_tcp_v3.TcpProxy_Cluster{
								Cluster: backend,
							},
						}),
					},
				},
			},
		})
	}

	return filterChains
}

// buildTLSSdsConfigs creates TLS SDS secret configs from TLS secrets.
// It deduplicates secrets by namespace/name and returns sorted configs.
func buildTLSSdsConfigs(ciliumSecretNamespace string, tls []model.TLSSecret) []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig {
	tlsMap := map[string]struct{}{}
	for _, t := range tls {
		tlsMap[fmt.Sprintf("%s/%s-%s", ciliumSecretNamespace, t.Namespace, t.Name)] = struct{}{}
	}

	// Sort keys for deterministic output
	sortedKeys := goslices.Sorted(maps.Keys(tlsMap))

	var configs []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig
	for _, k := range sortedKeys {
		configs = append(configs, &envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
			Name: k,
		})
	}
	return configs
}

func toTransportSocket(ciliumSecretNamespace string, tls []model.TLSSecret) (*envoy_config_core_v3.TransportSocket, error) {
	tlsSdsConfig := buildTLSSdsConfigs(ciliumSecretNamespace, tls)

	downStreamContext := envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: tlsSdsConfig,
		},
	}
	downstreamBytes, err := proto.Marshal(&downStreamContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal downstream TLS context: %w", err)
	}

	return &envoy_config_core_v3.TransportSocket{
		Name: tlsTransportSocketType,
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: envoy.DownstreamTlsContextURL,
				Value:   downstreamBytes,
			},
		},
	}, nil
}

func toFilterChainMatch(hostNames []string) *envoy_config_listener.FilterChainMatch {
	res := &envoy_config_listener.FilterChainMatch{
		TransportProtocol: tlsTransportProtocol,
	}
	// ServerNames must be sorted and unique, however, envoy don't support "*" as a server name
	serverNames := slices.SortedUnique(hostNames)
	if goslices.Contains(serverNames, "*") {
		return res
	}
	res.ServerNames = serverNames
	return res
}

// toQuicTransportSocket creates a QUIC transport socket for HTTP/3
func toQuicTransportSocket(ciliumSecretNamespace string, tls []model.TLSSecret) (*envoy_config_core_v3.TransportSocket, error) {
	tlsSdsConfig := buildTLSSdsConfigs(ciliumSecretNamespace, tls)

	downstreamTlsContext := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: tlsSdsConfig,
			AlpnProtocols:                  []string{"h3"}, // HTTP/3 ALPN
		},
	}

	quicTransportConfig := &envoy_extensions_transport_sockets_quic_v3.QuicDownstreamTransport{
		DownstreamTlsContext: downstreamTlsContext,
	}
	quicTransportBytes, err := proto.Marshal(quicTransportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal QUIC transport config: %w", err)
	}

	return &envoy_config_core_v3.TransportSocket{
		Name: quicTransportSocketType,
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: "type.googleapis.com/envoy.extensions.transport_sockets.quic.v3.QuicDownstreamTransport",
				Value:   quicTransportBytes,
			},
		},
	}, nil
}

// desiredQuicListener creates a UDP listener with QUIC transport for HTTP/3 on the specified port
func (i *cecTranslator) desiredQuicListener(m *model.Model, port uint32) (*envoy_config_listener.Listener, error) {
	// Get TLS secrets from HTTPS listeners (same certificates as HTTPS)
	tlsToHostnames := m.TLSSecretsToHostnames()
	if len(tlsToHostnames) == 0 {
		return nil, nil
	}

	orderedSecrets := goslices.SortedStableFunc(maps.Keys(tlsToHostnames), func(a, b model.TLSSecret) int {
		return cmp.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})

	// Create HTTP Connection Manager with HTTP/3 support (shared for all filter chains)
	http3ConnectionManagerName := fmt.Sprintf("%s-http3", listenerName)
	http3ConnectionManager, err := i.desiredHTTPConnectionManager(http3ConnectionManagerName, "listener-secure")
	if err != nil {
		return nil, err
	}

	// Unmarshal to add HTTP/3 options
	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	if err := proto.Unmarshal(http3ConnectionManager.Any.Value, hcm); err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP connection manager: %w", err)
	}

	// For QUIC listener, we must set CodecType to HTTP3
	// This is required by Envoy: "Non-HTTP/3 codec configured on QUIC listener"
	hcm.CodecType = httpConnectionManagerv3.HttpConnectionManager_HTTP3

	// Add HTTP/3 protocol options (optional, but recommended)
	hcm.Http3ProtocolOptions = &envoy_config_core_v3.Http3ProtocolOptions{}

	// Remove CommonHttpProtocolOptions if present, as it may conflict with HTTP/3
	// CommonHttpProtocolOptions is for HTTP/1.1 and HTTP/2, not HTTP/3
	hcm.CommonHttpProtocolOptions = nil

	// Re-marshal
	hcmBytes, err := proto.Marshal(hcm)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HTTP/3 connection manager: %w", err)
	}
	http3ConnectionManager.Any.Value = hcmBytes

	// For UDP/QUIC listener, we can only have ONE filter chain
	// QUIC handles SNI internally through TLS, so we use all TLS certificates
	// Create QUIC transport socket with all TLS certificates
	quicTransportSocket, err := toQuicTransportSocket(i.Config.SecretsNamespace, orderedSecrets)
	if err != nil {
		return nil, err
	}

	// UDP listener can only have one filter chain (no filterChainMatch for UDP)
	// According to Envoy HTTP/3 example: only http_connection_manager filter is needed
	// (no cilium.network filter for UDP listener)
	filterChains := []*envoy_config_listener.FilterChain{
		{
			TransportSocket: quicTransportSocket,
			Filters: []*envoy_config_listener.Filter{
				{
					Name: httpConnectionManagerType,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: http3ConnectionManager.Any,
					},
				},
			},
		},
	}

	// Create UDP listener with Host Network and IPv6 support
	udpAddress, additionalAddresses := getListenerAddresses([]uint32{port}, envoy_config_core_v3.SocketAddress_UDP, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled)
	udpListener := &envoy_config_listener.Listener{
		Name:      fmt.Sprintf("%s-udp-%d", listenerName, port),
		Address:   udpAddress,
		ReusePort: true, // Important for QUIC
		UdpListenerConfig: &envoy_config_listener.UdpListenerConfig{
			DownstreamSocketConfig: &envoy_config_core_v3.UdpSocketConfig{
				MaxRxDatagramSize: &wrapperspb.UInt64Value{Value: 1500},
			},
			QuicOptions: &envoy_config_listener.QuicProtocolOptions{
				// Empty QuicProtocolOptions enables QUIC with default settings
			},
		},
		FilterChains: filterChains,
	}
	if len(additionalAddresses) > 0 {
		udpListener.AdditionalAddresses = additionalAddresses
	}

	return udpListener, nil
}
