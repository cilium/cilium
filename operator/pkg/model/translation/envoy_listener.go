// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"cmp"
	"fmt"
	"maps"
	goslices "slices"
	"strings"
	"syscall"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_extensions_listener_proxy_protocol_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/proxy_protocol/v3"
	envoy_extensions_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
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

	rawBufferTransportProtocol = "raw_buffer"
	tlsTransportProtocol       = "tls"

	listenerName = "listener"
)

func listenerNameForPort(port uint32) string {
	return fmt.Sprintf("%s-%d", listenerName, port)
}

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

func withUseRemoteAddress(useRemoteAddress bool) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
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
						hcmConfig.UseRemoteAddress = wrapperspb.Bool(useRemoteAddress)
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

func withServerHeaderTransformation(m *model.Model) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		transformation := m.GetServerHeaderTransformation()
		// Skip if using Envoy's default (OVERWRITE, 0)
		if transformation == model.ServerHeaderTransformationOverwrite {
			return listener
		}
		for _, filterChain := range listener.FilterChains {
			for _, filter := range filterChain.Filters {
				if filter.Name != httpConnectionManagerType {
					continue
				}
				tc := filter.GetTypedConfig()
				if tc.GetTypeUrl() != envoy.HttpConnectionManagerTypeURL {
					continue
				}
				hcm, err := tc.UnmarshalNew()
				if err != nil {
					continue
				}
				hcmConfig, ok := hcm.(*httpConnectionManagerv3.HttpConnectionManager)
				if !ok {
					continue
				}
				var hcmTransform httpConnectionManagerv3.HttpConnectionManager_ServerHeaderTransformation
				switch transformation {
				case model.ServerHeaderTransformationAppendIfAbsent:
					hcmTransform = httpConnectionManagerv3.HttpConnectionManager_APPEND_IF_ABSENT
				case model.ServerHeaderTransformationPassThrough:
					hcmTransform = httpConnectionManagerv3.HttpConnectionManager_PASS_THROUGH
				default:
					continue
				}
				hcmConfig.ServerHeaderTransformation = hcmTransform
				filter.ConfigType = &envoy_config_listener.Filter_TypedConfig{TypedConfig: toAny(hcmConfig)}
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

func withHostNetworkPortSubset(ports []uint32, ipv4Enabled bool, ipv6Enabled bool) ListenerMutator {
	return func(listener *envoy_config_listener.Listener) *envoy_config_listener.Listener {
		listener.Address, listener.AdditionalAddresses = getHostNetworkListenerAddresses(ports, ipv4Enabled, ipv6Enabled)
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

// desiredEnvoyListener returns the desired Envoy listeners for the given model.
// When the model has multiple distinct HTTPS ports, one Listener is emitted per
// HTTPS port; otherwise a single combined Listener is returned.
func (i *cecTranslator) desiredEnvoyListener(m *model.Model) ([]ciliumv2.XDSResource, error) {
	if m.IsEmpty() {
		return nil, nil
	}

	if m.NeedsPerPortListeners() {
		return i.desiredEnvoyListenerPerPort(m)
	}
	return i.desiredEnvoyListenerCombined(m)
}

// desiredEnvoyListenerCombined returns a single Listener with all filter chains combined.
func (i *cecTranslator) desiredEnvoyListenerCombined(m *model.Model) ([]ciliumv2.XDSResource, error) {
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
	return []ciliumv2.XDSResource{res}, nil
}

// filterChains returns the filter chains for the given model.
func (i *cecTranslator) filterChains(name string, m *model.Model) ([]*envoy_config_listener.FilterChain, error) {
	var filterChains []*envoy_config_listener.FilterChain

	if m.IsHTTPListenerConfigured() {
		httpFilterChain, err := i.httpFilterChain(name, m)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, httpFilterChain)
	}

	if m.IsHTTPSListenerConfigured() {
		httpsFC, err := i.httpsFilterChains(name, m)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, httpsFC...)
	}

	if m.IsTLSPassthroughListenerConfigured() {
		filterChains = append(filterChains, tlsPassthroughFilterChains(m)...)
	}

	return filterChains, nil
}

// httpsFilterChains returns the HTTPS filter chains for the given model.
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

		secureHCMName := fmt.Sprintf("%s-%s", name, secureHost)
		secureHCM, err := i.desiredHTTPConnectionManager(secureHCMName, secureHCMName, m)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, &envoy_config_listener.FilterChain{
			FilterChainMatch: toFilterChainMatch(hostNames),
			Filters: []*envoy_config_listener.Filter{
				{
					Name: httpConnectionManagerType,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: secureHCM.Any,
					},
				},
			},
			TransportSocket: toTransportSocket(i.Config.SecretsNamespace, []model.TLSSecret{secret}),
		})
	}

	return filterChains, nil
}

// desiredEnvoyListenerPerPort returns one Listener per distinct HTTPS port
// and, when applicable, per TLS passthrough port.
func (i *cecTranslator) desiredEnvoyListenerPerPort(m *model.Model) ([]ciliumv2.XDSResource, error) {
	var allResources []ciliumv2.XDSResource

	needsPerPortTLS := m.NeedsPerPortTLSPassthroughListeners()

	// All TLS passthrough ports are excluded from the base insecure listener
	// port list, since they are handled by their own section (either per-port
	// listeners or a combined TLS passthrough block on the base listener).
	tlsPassthroughPorts := map[uint32]bool{}
	for _, p := range m.TLSPassthroughPorts() {
		tlsPassthroughPorts[p] = true
	}

	hasInsecure := false
	for _, l := range m.HTTP {
		if len(l.TLS) == 0 && !tlsPassthroughPorts[l.Port] {
			hasInsecure = true
			break
		}
	}

	hasTLSPassthroughForBase := !needsPerPortTLS && m.IsTLSPassthroughListenerConfigured()

	if hasInsecure || hasTLSPassthroughForBase {
		var filterChains []*envoy_config_listener.FilterChain

		if hasInsecure {
			httpFC, err := i.httpFilterChain(listenerName, m)
			if err != nil {
				return nil, err
			}
			filterChains = append(filterChains, httpFC)
		}

		if hasTLSPassthroughForBase {
			filterChains = append(filterChains, tlsPassthroughFilterChains(m)...)
		}

		insecureListener := &envoy_config_listener.Listener{
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
		var basePorts []uint32
		for _, hl := range m.HTTP {
			if len(hl.TLS) == 0 && !tlsPassthroughPorts[hl.Port] {
				basePorts = append(basePorts, hl.Port)
			}
		}
		if hasTLSPassthroughForBase {
			basePorts = append(basePorts, m.TLSPassthroughPorts()...)
		}
		goslices.Sort(basePorts)
		basePorts = goslices.Compact(basePorts)
		for _, fn := range i.listenerMutatorsForPorts(m, basePorts) {
			insecureListener = fn(insecureListener)
		}
		res, err := toXdsResource(insecureListener, envoy.ListenerTypeURL)
		if err != nil {
			return nil, err
		}
		allResources = append(allResources, res)
	}

	// one Listener per HTTPS port
	for _, port := range m.HTTPSPortsSorted() {
		lName := listenerNameForPort(port)

		httpsFC, err := i.httpsFilterChainsForPort(lName, port, m)
		if err != nil {
			return nil, err
		}
		if len(httpsFC) == 0 {
			continue
		}

		httpsListener := &envoy_config_listener.Listener{
			Name:         lName,
			FilterChains: httpsFC,
			ListenerFilters: []*envoy_config_listener.ListenerFilter{
				{
					Name: tlsInspectorType,
					ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
						TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
					},
				},
			},
		}
		for _, fn := range i.listenerMutatorsForPorts(m, []uint32{port}) {
			httpsListener = fn(httpsListener)
		}
		res, err := toXdsResource(httpsListener, envoy.ListenerTypeURL)
		if err != nil {
			return nil, err
		}
		allResources = append(allResources, res)
	}

	// One Listener per TLS passthrough port.
	if needsPerPortTLS {
		for _, port := range m.TLSPassthroughPorts() {
			lName := listenerNameForPort(port)

			tlsFC := tlsPassthroughFilterChainsForPort(port, m)
			if len(tlsFC) == 0 {
				continue
			}

			tlsListener := &envoy_config_listener.Listener{
				Name:         lName,
				FilterChains: tlsFC,
				ListenerFilters: []*envoy_config_listener.ListenerFilter{
					{
						Name: tlsInspectorType,
						ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{
							TypedConfig: toAny(&envoy_extensions_listener_tls_inspector_v3.TlsInspector{}),
						},
					},
				},
			}
			for _, fn := range i.listenerMutatorsForPorts(m, []uint32{port}) {
				tlsListener = fn(tlsListener)
			}
			res, err := toXdsResource(tlsListener, envoy.ListenerTypeURL)
			if err != nil {
				return nil, err
			}
			allResources = append(allResources, res)
		}
	}

	return allResources, nil
}

// listenerMutators returns a list of listener mutators to apply to the listener.
func (i *cecTranslator) listenerMutators(m *model.Model) []ListenerMutator {
	return i.listenerMutatorsForPorts(m, m.AllPorts())
}

// listenerMutatorsForPorts returns listener mutators for the given port subset.
func (i *cecTranslator) listenerMutatorsForPorts(m *model.Model, ports []uint32) []ListenerMutator {
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
		res = append(res, withHostNetworkPortSubset(ports, i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled))
	}

	if i.Config.ListenerConfig.StreamIdleTimeoutSeconds > 0 {
		res = append(res, WithStreamIdleTimeout(i.Config.ListenerConfig.StreamIdleTimeoutSeconds))
	}

	res = append(res, withUseRemoteAddress(i.Config.OriginalIPDetectionConfig.UseRemoteAddress))

	if i.Config.OriginalIPDetectionConfig.XFFNumTrustedHops > 0 {
		res = append(res, withXffNumTrustedHops(i.Config.OriginalIPDetectionConfig.XFFNumTrustedHops))
	}

	res = append(res, withServerHeaderTransformation(m))
	return res
}

func (i *cecTranslator) httpFilterChain(name string, m *model.Model) (*envoy_config_listener.FilterChain, error) {
	insecureHttpConnectionManagerName := fmt.Sprintf("%s-insecure", name)
	insecureHttpConnectionManager, err := i.desiredHTTPConnectionManager(
		insecureHttpConnectionManagerName,
		insecureHttpConnectionManagerName,
		m,
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

// httpsFilterChainsForPort returns the HTTPS filter chains for the given port.
func (i *cecTranslator) httpsFilterChainsForPort(name string, port uint32, m *model.Model) ([]*envoy_config_listener.FilterChain, error) {
	tlsToListeners := m.TLSSecretsToListeners()
	if len(tlsToListeners) == 0 {
		return nil, nil
	}

	hostsBySecret := map[model.TLSSecret][]string{}
	for secret, refs := range tlsToListeners {
		for _, ref := range refs {
			if ref.Port == port {
				hostsBySecret[secret] = append(hostsBySecret[secret], ref.Hostname)
			}
		}
	}

	if len(hostsBySecret) == 0 {
		return nil, nil
	}

	orderedSecrets := make([]model.TLSSecret, 0, len(hostsBySecret))
	for secret := range hostsBySecret {
		orderedSecrets = append(orderedSecrets, secret)
	}
	goslices.SortStableFunc(orderedSecrets, func(a, b model.TLSSecret) int {
		return cmp.Compare(a.Namespace+"/"+a.Name, b.Namespace+"/"+b.Name)
	})

	var filterChains []*envoy_config_listener.FilterChain
	for _, secret := range orderedSecrets {
		hostNames := hostsBySecret[secret]

		hcm, err := i.desiredHTTPConnectionManager(name, name, m)
		if err != nil {
			return nil, err
		}
		filterChains = append(filterChains, &envoy_config_listener.FilterChain{
			FilterChainMatch: toFilterChainMatch(hostNames),
			Filters: []*envoy_config_listener.Filter{
				{
					Name: httpConnectionManagerType,
					ConfigType: &envoy_config_listener.Filter_TypedConfig{
						TypedConfig: hcm.Any,
					},
				},
			},
			TransportSocket: toTransportSocket(i.Config.SecretsNamespace, []model.TLSSecret{secret}),
		})
	}

	return filterChains, nil
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

// tlsPassthroughFilterChains returns TLS passthrough filter chains for all backends.
// These functions do not depend on cecTranslator state, so they are defined as
// package-level helpers rather than receiver methods.
func tlsPassthroughFilterChains(m *model.Model) []*envoy_config_listener.FilterChain {
	var filterChains []*envoy_config_listener.FilterChain

	for _, listener := range stableTLSPassthroughListeners(m.TLSPassthrough) {
		for _, route := range stableTLSPassthroughRoutes(listener.Routes) {
			backends := stableTLSPassthroughBackends(route.Backends)
			if len(backends) == 0 {
				continue
			}

			tcpProxy := tcpProxyForTLSPassthroughRoute(route, backends)
			tcpProxy.AccessLog = getTCPAccessLogs(m)
			filterChains = append(filterChains, &envoy_config_listener.FilterChain{
				FilterChainMatch: toFilterChainMatch(route.Hostnames),
				Filters: []*envoy_config_listener.Filter{
					{
						Name: tcpProxyType,
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: toAny(tcpProxy),
						},
					},
				},
			})
		}
	}

	return filterChains
}

// tlsPassthroughFilterChainsForPort returns TLS passthrough filter chains for
// routes on a specific port, used when per-port listeners are needed to scope
// filter chains to the routes attached to a single listener port.
func tlsPassthroughFilterChainsForPort(port uint32, m *model.Model) []*envoy_config_listener.FilterChain {
	var filterChains []*envoy_config_listener.FilterChain

	for _, listener := range stableTLSPassthroughListeners(m.TLSPassthrough) {
		if listener.Port != port {
			continue
		}
		for _, route := range stableTLSPassthroughRoutes(listener.Routes) {
			backends := stableTLSPassthroughBackends(route.Backends)
			if len(backends) == 0 {
				continue
			}

			filterChains = append(filterChains, &envoy_config_listener.FilterChain{
				FilterChainMatch: toFilterChainMatch(route.Hostnames),
				Filters: []*envoy_config_listener.Filter{
					{
						Name: tcpProxyType,
						ConfigType: &envoy_config_listener.Filter_TypedConfig{
							TypedConfig: toAny(tcpProxyForTLSPassthroughRoute(route, backends)),
						},
					},
				},
			})
		}
	}

	return filterChains
}

func stableTLSPassthroughListeners(listeners []model.TLSPassthroughListener) []model.TLSPassthroughListener {
	if len(listeners) < 2 {
		return listeners
	}

	stable := append([]model.TLSPassthroughListener(nil), listeners...)
	goslices.SortFunc(stable, func(a, b model.TLSPassthroughListener) int {
		return cmp.Or(
			cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.Address, b.Address),
			cmp.Compare(a.Hostname, b.Hostname),
			cmp.Compare(a.Name, b.Name),
		)
	})

	return stable
}

func stableTLSPassthroughRoutes(routes []model.TLSPassthroughRoute) []model.TLSPassthroughRoute {
	if len(routes) < 2 {
		return routes
	}

	stable := append([]model.TLSPassthroughRoute(nil), routes...)
	goslices.SortFunc(stable, func(a, b model.TLSPassthroughRoute) int {
		return cmp.Or(
			cmp.Compare(tlsPassthroughHostnamesKey(a.Hostnames), tlsPassthroughHostnamesKey(b.Hostnames)),
			cmp.Compare(tlsPassthroughBackendsKey(a.Backends), tlsPassthroughBackendsKey(b.Backends)),
			cmp.Compare(a.Name, b.Name),
		)
	})

	return stable
}

func stableTLSPassthroughBackends(backends []model.Backend) []model.Backend {
	if len(backends) < 2 {
		return backends
	}

	stable := append([]model.Backend(nil), backends...)
	goslices.SortFunc(stable, func(a, b model.Backend) int {
		return cmp.Or(
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(tlsPassthroughBackendPort(a), tlsPassthroughBackendPort(b)),
			cmp.Compare(tlsPassthroughBackendWeight(a), tlsPassthroughBackendWeight(b)),
		)
	})

	return stable
}

func tcpProxyForTLSPassthroughRoute(route model.TLSPassthroughRoute, backends []model.Backend) *envoy_extensions_filters_network_tcp_v3.TcpProxy {
	tcpProxy := &envoy_extensions_filters_network_tcp_v3.TcpProxy{
		StatPrefix: tlsPassthroughFilterChainStatPrefix(route),
	}

	if len(backends) == 1 {
		tcpProxy.ClusterSpecifier = &envoy_extensions_filters_network_tcp_v3.TcpProxy_Cluster{
			Cluster: tlsPassthroughClusterName(backends[0]),
		}
		return tcpProxy
	}

	weightedClusters := make([]*envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight, 0, len(backends))
	for _, backend := range backends {
		weightedClusters = append(weightedClusters, &envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster_ClusterWeight{
			Name:   tlsPassthroughClusterName(backend),
			Weight: tlsPassthroughBackendWeight(backend),
		})
	}

	tcpProxy.ClusterSpecifier = &envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedClusters{
		WeightedClusters: &envoy_extensions_filters_network_tcp_v3.TcpProxy_WeightedCluster{
			Clusters: weightedClusters,
		},
	}

	return tcpProxy
}

func tlsPassthroughClusterName(backend model.Backend) string {
	return getClusterName(backend.Namespace, backend.Name, backend.Port.GetPort())
}

func tlsPassthroughFilterChainStatPrefix(route model.TLSPassthroughRoute) string {
	return "tls-passthrough:" + tlsPassthroughHostnamesKey(route.Hostnames)
}

func tlsPassthroughHostnamesKey(hostnames []string) string {
	if len(hostnames) == 0 {
		return "*"
	}

	stable := append([]string(nil), hostnames...)
	goslices.Sort(stable)
	return strings.Join(stable, ",")
}

func tlsPassthroughBackendsKey(backends []model.Backend) string {
	stable := stableTLSPassthroughBackends(backends)
	keys := make([]string, 0, len(stable))
	for _, backend := range stable {
		keys = append(keys, fmt.Sprintf("%s/%s:%s:%d", backend.Namespace, backend.Name, tlsPassthroughBackendPort(backend), tlsPassthroughBackendWeight(backend)))
	}
	return strings.Join(keys, ",")
}

func tlsPassthroughBackendPort(backend model.Backend) string {
	if backend.Port == nil {
		return ""
	}
	return backend.Port.GetPort()
}

func tlsPassthroughBackendWeight(backend model.Backend) uint32 {
	if backend.Weight == nil {
		return 1
	}
	// Gateway API validates non-negative weights, but clamp defensively for
	// internal model callers.
	if *backend.Weight < 0 {
		return 0
	}
	return uint32(*backend.Weight)
}

func toTransportSocket(ciliumSecretNamespace string, tls []model.TLSSecret) *envoy_config_core_v3.TransportSocket {
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
	downstreamBytes, _ := proto.Marshal(&downStreamContext)

	return &envoy_config_core_v3.TransportSocket{
		Name: tlsTransportSocketType,
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: &anypb.Any{
				TypeUrl: envoy.DownstreamTlsContextURL,
				Value:   downstreamBytes,
			},
		},
	}
}

func toFilterChainMatch(hostNames []string) *envoy_config_listener.FilterChainMatch {
	res := &envoy_config_listener.FilterChainMatch{
		TransportProtocol: tlsTransportProtocol,
	}
	// ServerNames must be sorted and unique, and Envoy does not support "*" as a server name.
	serverNames := slices.SortedUnique(hostNames)
	if goslices.Contains(serverNames, "*") {
		return res
	}
	res.ServerNames = serverNames
	return res
}
