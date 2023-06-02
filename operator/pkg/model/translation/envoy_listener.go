// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"syscall"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/listener/tls_inspector/v3"
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
	tlsTransportSocketType    = "envoy.transport_sockets.tls"

	rawBufferTransportProtocol = "raw_buffer"
	tlsTransportProtocol       = "tls"
)

type ListenerMutator func(*envoy_config_listener.Listener) *envoy_config_listener.Listener

func WithSocketOption(tcpKeepAlive, tcpKeepIdleInSeconds, tcpKeepAliveProbeIntervalInSeconds, tcpKeepAliveMaxFailures int64) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		listener.SocketOptions = []*envoy_config_core_v3.SocketOption{
			{
				Description: "Enable TCP keep-alive (default to enabled)",
				Level:       syscall.SOL_SOCKET,
				Name:        syscall.SO_KEEPALIVE,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepAlive,
				},
				State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
			},
			{
				Description: "TCP keep-alive idle time (in seconds) (defaults to 10s)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPIDLE,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepIdleInSeconds,
				},
				State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
			},
			{
				Description: "TCP keep-alive probe intervals (in seconds) (defaults to 5s)",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPINTVL,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepAliveProbeIntervalInSeconds,
				},
				State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
			},
			{
				Description: "TCP keep-alive probe max failures.",
				Level:       syscall.IPPROTO_TCP,
				Name:        syscall.TCP_KEEPCNT,
				Value: &envoy_config_core_v3.SocketOption_IntValue{
					IntValue: tcpKeepAliveMaxFailures,
				},
				State: envoy_config_core_v3.SocketOption_STATE_LISTENING,
			},
		}
		return listener
	}
}

// NewHTTPListenerWithDefaults same as NewListener but with default mutators applied.
func NewHTTPListenerWithDefaults(name string, ciliumSecretNamespace string, tls map[model.TLSSecret][]string, mutatorFunc ...ListenerMutator) (ciliumv2.XDSResource, error) {
	fns := append(mutatorFunc,
		WithSocketOption(
			defaultTCPKeepAlive,
			defaultTCPKeepAliveIdleTimeInSeconds,
			defaultTCPKeepAliveProbeIntervalInSeconds,
			defaultTCPKeepAliveMaxFailures),
	)
	return NewHTTPListener(name, ciliumSecretNamespace, tls, fns...)
}

// NewHTTPListener creates a new Envoy listener with the given name.
// The listener will have both secure and insecure filters.
// Secret Discovery Service (SDS) is used to fetch the TLS certificates.
func NewHTTPListener(name string, ciliumSecretNamespace string, tls map[model.TLSSecret][]string, mutatorFunc ...ListenerMutator) (ciliumv2.XDSResource, error) {
	var filterChains []*envoy_config_listener.FilterChain

	insecureHttpConnectionManagerName := fmt.Sprintf("%s-insecure", name)
	insecureHttpConnectionManager, err := NewHTTPConnectionManager(insecureHttpConnectionManagerName, insecureHttpConnectionManagerName)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	filterChains = append(filterChains, &envoy_config_listener.FilterChain{
		FilterChainMatch: &envoy_config_listener.FilterChainMatch{TransportProtocol: rawBufferTransportProtocol},
		Filters: []*envoy_config_listener.Filter{
			{
				Name: httpConnectionManagerType,
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: insecureHttpConnectionManager.Any,
				},
			},
		},
	})

	for secret, hostNames := range tls {
		secureHttpConnectionManagerName := fmt.Sprintf("%s-secure", name)
		secureHttpConnectionManager, err := NewHTTPConnectionManager(secureHttpConnectionManagerName, secureHttpConnectionManagerName)
		if err != nil {
			return ciliumv2.XDSResource{}, err
		}

		transportSocket, err := newTransportSocket(ciliumSecretNamespace, []model.TLSSecret{secret})
		if err != nil {
			return ciliumv2.XDSResource{}, err
		}

		filterChains = append(filterChains, &envoy_config_listener.FilterChain{
			FilterChainMatch: &envoy_config_listener.FilterChainMatch{
				ServerNames:       slices.SortedUnique(hostNames),
				TransportProtocol: tlsTransportProtocol,
			},
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

	listener := &envoy_config_listener.Listener{
		Name:         name,
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

	for _, fn := range mutatorFunc {
		listener = fn(listener)
	}

	listenerBytes, err := proto.Marshal(listener)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}
	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ListenerTypeURL,
			Value:   listenerBytes,
		},
	}, nil
}

// NewSNIListenerWithDefaults same as NewSNIListener but with default mutators applied.
func NewSNIListenerWithDefaults(name string, backendsForHost map[string][]string, mutatorFunc ...ListenerMutator) (ciliumv2.XDSResource, error) {
	fns := append(mutatorFunc,
		WithSocketOption(
			defaultTCPKeepAlive,
			defaultTCPKeepAliveIdleTimeInSeconds,
			defaultTCPKeepAliveProbeIntervalInSeconds,
			defaultTCPKeepAliveMaxFailures),
	)
	return NewSNIListener(name, backendsForHost, fns...)
}

// NewSNIListener creates a new Envoy listener with the given name.
// The listener will be configured to use SNI to determine thhe backend
func NewSNIListener(name string, backendsForHost map[string][]string, mutatorFunc ...ListenerMutator) (ciliumv2.XDSResource, error) {
	var filterChains []*envoy_config_listener.FilterChain

	for backed, hostNames := range backendsForHost {
		filterChains = append(filterChains, &envoy_config_listener.FilterChain{
			FilterChainMatch: &envoy_config_listener.FilterChainMatch{
				ServerNames:       slices.SortedUnique(hostNames),
				TransportProtocol: tlsTransportProtocol,
			},
			Filters: []*envoy_config_listener.Filter{
				{
					Name: tcpProxyType,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: toAny(&envoy_extensions_filters_network_tcp_v3.TcpProxy{
							StatPrefix: backed,
							ClusterSpecifier: &envoy_extensions_filters_network_tcp_v3.TcpProxy_Cluster{
								Cluster: backed,
							},
						}),
					},
				},
			},
		})
	}

	listener := &envoy_config_listener.Listener{
		Name:         name,
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

	for _, fn := range mutatorFunc {
		listener = fn(listener)
	}

	listenerBytes, err := proto.Marshal(listener)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}
	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: envoy.ListenerTypeURL,
			Value:   listenerBytes,
		},
	}, nil
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
			SdsConfig: &envoy_config_core_v3.ConfigSource{
				ConfigSourceSpecifier: &envoy_config_core_v3.ConfigSource_ApiConfigSource{
					ApiConfigSource: &envoy_config_core_v3.ApiConfigSource{
						ApiType:             envoy_config_core_v3.ApiConfigSource_GRPC,
						TransportApiVersion: envoy_config_core_v3.ApiVersion_V3,
						GrpcServices: []*envoy_config_core_v3.GrpcService{
							{
								TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
									EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
										ClusterName: envoy.CiliumXDSClusterName,
									},
								},
							},
						},
					},
				},
				ResourceApiVersion: envoy_config_core_v3.ApiVersion_V3,
			},
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
