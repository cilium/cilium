// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	"maps"
	goslices "slices"
	"syscall"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_extensions_listener_proxy_protocol_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
	httpConnectionManagerv3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

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

func withHostNetworkPort(m *model.Model, ipv4Enabled bool, ipv6Enabled bool) ListenerMutator {
	ports := []uint32{}
	for _, hl := range m.HTTP {
		ports = append(ports, hl.GetPort())
	}
	for _, hl := range m.TLSPassthrough {
		ports = append(ports, hl.GetPort())
	}

	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		listener.Address, listener.AdditionalAddresses = getHostNetworkListenerAddresses(slices.SortedUnique(ports), ipv4Enabled, ipv6Enabled)

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
func (i *cecTranslator) desiredEnvoyListener(m *model.Model) []ciliumv2.XDSResource {
	if len(m.HTTP) == 0 && len(m.TLSPassthrough) == 0 {
		return nil
	}

	listener := &envoy_config_listener.Listener{
		Name:         listenerName,
		FilterChains: i.filterChains(listenerName, m),
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

	res, _ := toXdsResource(listener, envoy.ListenerTypeURL)
	return []ciliumv2.XDSResource{res}
}

func (i *cecTranslator) filterChains(name string, m *model.Model) []*envoy_config_listener.FilterChain {
	var filterChains []*envoy_config_listener.FilterChain

	if len(m.HTTP) > 0 {
		httpFilterChain, err := i.httpFilterChain(name, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled)
		if err != nil {
			return nil
		}
		filterChains = append(filterChains, httpFilterChain)
	}

	httpsFilterChains, err := i.httpsFilterChains(name, i.Config.SecretsNamespace, tlsSecretsToHostnames(m), i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled)
	if err != nil {
		return nil
	}
	filterChains = append(filterChains, httpsFilterChains...)

	filterChains = append(filterChains, tlsPassthroughFilterChains(tlsPassthroughBackendsToHostnames(m))...)

	return filterChains
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

	if i.Config.OriginalIPDetectionConfig.XFFNumTrustedHops > 0 {
		res = append(res, withXffNumTrustedHops(i.Config.OriginalIPDetectionConfig.XFFNumTrustedHops))
	}
	return res
}

func (i *cecTranslator) httpFilterChain(name string, enableIpv4 bool, enableIpv6 bool) (*envoy_config_listener.FilterChain, error) {
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

func (i *cecTranslator) httpsFilterChains(name string, ciliumSecretNamespace string, tlsSecretsToHostnames map[model.TLSSecret][]string,
	enableIpv4 bool, enableIpv6 bool) ([]*envoy_config_listener.FilterChain, error) {
	if len(tlsSecretsToHostnames) == 0 {
		return nil, nil
	}

	var filterChains []*envoy_config_listener.FilterChain

	orderedSecrets := goslices.SortedStableFunc(maps.Keys(tlsSecretsToHostnames), func(a, b model.TLSSecret) int {
		return cmp.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})

	for _, secret := range orderedSecrets {
		hostNames := tlsSecretsToHostnames[secret]

		secureHttpConnectionManagerName := fmt.Sprintf("%s-secure", name)
		secureHttpConnectionManager, err := i.desiredHTTPConnectionManager(secureHttpConnectionManagerName, secureHttpConnectionManagerName)
		if err != nil {
			return nil, err
		}

		transportSocket, err := newTransportSocket(ciliumSecretNamespace, []model.TLSSecret{secret})
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

func tlsPassthroughBackendsToHostnames(m *model.Model) map[string][]string {
	res := make(map[string][]string)
	for _, h := range m.TLSPassthrough {
		for _, route := range h.Routes {
			for _, backend := range route.Backends {
				key := fmt.Sprintf("%s:%s:%s", backend.Namespace, backend.Name, backend.Port.GetPort())
				res[key] = append(res[key], route.Hostnames...)
			}
		}
	}
	return res
}

func getHostNetworkListenerAddresses(ports []uint32, ipv4Enabled, ipv6Enabled bool) (*envoy_config_core_v3.Address, []*envoy_config_listener.AdditionalAddress) {
	if len(ports) == 0 || (!ipv4Enabled && !ipv6Enabled) {
		return nil, nil
	}

	bindAddresses := []string{}
	if ipv4Enabled {
		bindAddresses = append(bindAddresses, "0.0.0.0")
	}
	if ipv6Enabled {
		bindAddresses = append(bindAddresses, "::")
	}

	addresses := []*envoy_config_core_v3.Address_SocketAddress{}

	for _, p := range ports {
		for _, a := range bindAddresses {
			addresses = append(addresses, &envoy_config_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_config_core_v3.SocketAddress{
					Protocol:      envoy_config_core_v3.SocketAddress_TCP,
					Address:       a,
					PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: p},
				},
			})
		}
	}

	var additionalAddress []*envoy_config_listener.AdditionalAddress

	if len(addresses) > 1 {
		for _, a := range addresses[1:] {
			additionalAddress = append(additionalAddress, &envoy_config_listener.AdditionalAddress{
				Address: &envoy_config_core_v3.Address{
					Address: a,
				},
			})
		}
	}

	return &envoy_config_core_v3.Address{
		Address: addresses[0],
	}, additionalAddress
}

func tlsSecretsToHostnames(m *model.Model) map[model.TLSSecret][]string {
	res := make(map[model.TLSSecret][]string)
	for _, h := range m.HTTP {
		for _, s := range h.TLS {
			res[s] = append(res[s], h.Hostname)
		}
	}

	return res
}

func tlsPassthroughFilterChains(ptBackendsToHostnames map[string][]string) []*envoy_config_listener.FilterChain {
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

func newTransportSocket(ciliumSecretNamespace string, tls []model.TLSSecret) (*envoy_config_core_v3.TransportSocket, error) {
	var tlsSdsConfig []*envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig
	tlsMap := map[string]struct{}{}
	for _, t := range tls {
		tlsMap[fmt.Sprintf("%s/%s-%s", ciliumSecretNamespace, t.Namespace, t.Name)] = struct{}{}
	}

	for k := range tlsMap {
		tlsSdsConfig = append(tlsSdsConfig, &envoy_extensions_transport_sockets_tls_v3.SdsSecretConfig{
			Name: k,
		})
	}

	downStreamContext := envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: tlsSdsConfig,
		},
	}

	downstreamBytes, err := proto.Marshal(&downStreamContext)
	if err != nil {
		return nil, err
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
