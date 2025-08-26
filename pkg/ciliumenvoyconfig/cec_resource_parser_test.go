// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_http_healthcheck "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/health_check/v3"
	envoy_upstream_codec "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/upstream_codec/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/envoy"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
)

type MockPort struct {
	port uint16
	cnt  int
}

type MockPortAllocator struct {
	mu    lock.Mutex
	port  uint16
	ports map[string]*MockPort
}

func NewMockPortAllocator() *MockPortAllocator {
	return &MockPortAllocator{
		port:  1024,
		ports: make(map[string]*MockPort),
	}
}

func (m *MockPortAllocator) AllocateCRDProxyPort(name string) (uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if mp, exists := m.ports[name]; exists {
		return mp.port, nil
	}
	m.port++
	m.ports[name] = &MockPort{port: m.port}

	return m.port, nil
}

func (m *MockPortAllocator) AckProxyPortWithReference(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mp, exists := m.ports[name]
	if !exists {
		return fmt.Errorf("Non-allocated port %s", name)
	}
	mp.cnt++
	return nil
}

func (m *MockPortAllocator) ReleaseProxyPort(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mp, exists := m.ports[name]
	if !exists {
		return fmt.Errorf("Non-allocated port %s", name)
	}
	mp.cnt--
	if mp.cnt <= 0 {
		delete(m.ports, name)
	}
	return nil
}

func TestUpstreamInject(t *testing.T) {
	//
	// Empty options
	//
	var opts envoy_upstreams_http_v3.HttpProtocolOptions
	changed, err := injectCiliumUpstreamL7Filter(&opts, false)
	assert.NoError(t, err)
	assert.True(t, changed)
	assert.NotNil(t, opts.HttpFilters)
	assert.Len(t, opts.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", opts.HttpFilters[0].Name)
	assert.Equal(t, ciliumL7FilterTypeURL, opts.HttpFilters[0].GetTypedConfig().TypeUrl)
	assert.Equal(t, "envoy.filters.http.upstream_codec", opts.HttpFilters[1].Name)
	assert.Equal(t, upstreamCodecFilterTypeURL, opts.HttpFilters[1].GetTypedConfig().TypeUrl)
	//
	// Check injected UpstreamProtocolOptions
	//
	assert.NotNil(t, opts.GetUseDownstreamProtocolConfig()) // no ALPN support

	// already present
	changed, err = injectCiliumUpstreamL7Filter(&opts, true)
	assert.NoError(t, err)
	assert.False(t, changed)
	assert.NotNil(t, opts.HttpFilters)
	assert.Len(t, opts.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", opts.HttpFilters[0].Name)
	assert.Equal(t, ciliumL7FilterTypeURL, opts.HttpFilters[0].GetTypedConfig().TypeUrl)
	assert.Equal(t, "envoy.filters.http.upstream_codec", opts.HttpFilters[1].Name)
	assert.Equal(t, upstreamCodecFilterTypeURL, opts.HttpFilters[1].GetTypedConfig().TypeUrl)
	//
	// Existing Upstream protocol options are not overridden
	//
	assert.NotNil(t, opts.GetUseDownstreamProtocolConfig())

	// missing codec
	opts = envoy_upstreams_http_v3.HttpProtocolOptions{
		HttpFilters: []*envoy_config_http.HttpFilter{
			{
				Name: "cilium.l7policy",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&cilium.L7Policy{}),
				},
			},
		},
	}
	changed, err = injectCiliumUpstreamL7Filter(&opts, true)
	assert.NoError(t, err)
	assert.True(t, changed)
	assert.NotNil(t, opts.HttpFilters)
	assert.Len(t, opts.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", opts.HttpFilters[0].Name)
	assert.Equal(t, ciliumL7FilterTypeURL, opts.HttpFilters[0].GetTypedConfig().TypeUrl)
	assert.Equal(t, "envoy.filters.http.upstream_codec", opts.HttpFilters[1].Name)
	assert.Equal(t, upstreamCodecFilterTypeURL, opts.HttpFilters[1].GetTypedConfig().TypeUrl)
	assert.NotNil(t, opts.GetAutoConfig()) // with ALPN support

	// codec present
	opts = envoy_upstreams_http_v3.HttpProtocolOptions{
		HttpFilters: []*envoy_config_http.HttpFilter{
			{
				Name: "envoy.filters.http.upstream_codec",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&envoy_upstream_codec.UpstreamCodec{}),
				},
			},
		},
	}
	changed, err = injectCiliumUpstreamL7Filter(&opts, true)
	assert.NoError(t, err)
	assert.True(t, changed)
	assert.NotNil(t, opts.HttpFilters)
	assert.Len(t, opts.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", opts.HttpFilters[0].Name)
	assert.Equal(t, ciliumL7FilterTypeURL, opts.HttpFilters[0].GetTypedConfig().TypeUrl)
	assert.Equal(t, "envoy.filters.http.upstream_codec", opts.HttpFilters[1].Name)
	assert.Equal(t, upstreamCodecFilterTypeURL, opts.HttpFilters[1].GetTypedConfig().TypeUrl)
	assert.NotNil(t, opts.GetAutoConfig()) // with ALPN support

	// wrong order
	// codec present
	opts = envoy_upstreams_http_v3.HttpProtocolOptions{
		HttpFilters: []*envoy_config_http.HttpFilter{
			{
				Name: "envoy.filters.http.upstream_codec",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&envoy_upstream_codec.UpstreamCodec{}),
				},
			},
			{
				Name: "cilium.l7policy",
				ConfigType: &envoy_config_http.HttpFilter_TypedConfig{
					TypedConfig: toAny(&cilium.L7Policy{}),
				},
			},
		},
	}
	changed, err = injectCiliumUpstreamL7Filter(&opts, true)
	assert.Error(t, err)
	assert.False(t, changed)
	assert.ErrorContains(t, err, "filter after codec filter: name:\"cilium.l7policy\"")
}

var xds1 = `version_info: "0"
resources:
- "@type": type.googleapis.com/envoy.config.listener.v3.Listener
  name: listener_0
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 10000
  filter_chains:
  - filters:
    - name: envoy.filters.network.http_connection_manager
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
        stat_prefix: ingress_http
        codec_type: AUTO
        route_config:
          virtual_hosts:
          - name: "prometheus_metrics_route"
            domains: ["*"]
            routes:
            - match:
                path: "/metrics"
              route:
                cluster: "/envoy-admin"
                prefix_rewrite: "/stats/prometheus"
        use_remote_address: true
        skip_xff_append: true
        http_filters:
        - name: envoy.filters.http.router
`

func TestCiliumEnvoyConfigSpec(t *testing.T) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(xds1))
	require.NoError(t, err)

	spec := cilium_v2.CiliumEnvoyConfigSpec{}
	err = json.Unmarshal(jsonBytes, &spec)
	require.NoError(t, err)

	assert.Len(t, spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", spec.Resources[0].TypeUrl)
	message, err := spec.Resources[0].UnmarshalNew()
	require.NoError(t, err)

	listener, ok := message.(*envoy_config_listener.Listener)
	assert.True(t, ok)
	assert.Equal(t, "listener_0", listener.Name)
}

var ciliumEnvoyConfig = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-prometheus-metrics-listener
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          rds:
            route_config_name: local_route
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            tls_certificate_sds_secret_configs:
            - name: cilium-secrets/server-mtls
            validation_context_sds_secret_config:
              name: validation_context
  - "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
    name: validation_context
    validation_context:
      trusted_ca:
        filename: /etc/ssl/certs/ca-certificates.crt
`

func TestCiliumEnvoyConfig(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfig))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.NotNil(t, cec.Spec.Resources)
	assert.Len(t, cec.Spec.Resources, 2)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)
	assert.Equal(t, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret", cec.Spec.Resources[1].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/envoy-prometheus-metrics-listener", resources.Listeners[0].Name)
	assert.Equal(t, uint32(10000), resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]

	assert.NotNil(t, chain.TransportSocket)
	assert.Equal(t, "envoy.transport_sockets.tls", chain.TransportSocket.Name)
	msg, err := chain.TransportSocket.GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, msg)
	tls, ok := msg.(*envoy_config_tls.DownstreamTlsContext)
	assert.True(t, ok)
	assert.NotNil(t, tls)
	//
	// Check that missing SDS config sources are automatically filled in
	//
	tlsContext := tls.CommonTlsContext
	assert.NotNil(t, tlsContext)
	for _, sc := range tlsContext.TlsCertificateSdsSecretConfigs {
		checkCiliumXDS(t, sc.SdsConfig)
		// Check that the already qualified secret name was not changed
		assert.Equal(t, "cilium-secrets/server-mtls", sc.Name)
	}
	sdsConfig := tlsContext.GetValidationContextSdsSecretConfig()
	assert.NotNil(t, sdsConfig)
	checkCiliumXDS(t, sdsConfig.SdsConfig)
	// Check that secret name was qualified
	assert.Equal(t, "namespace/name/validation_context", sdsConfig.Name)

	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)

	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	require.NotNil(t, rds)
	assert.Equal(t, "namespace/name/local_route", rds.RouteConfigName)
	checkCiliumXDS(t, rds.GetConfigSource())

	//
	// Check that HTTP filters are parsed
	//
	assert.Len(t, hcm.HttpFilters, 1)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[0].Name)

	//
	// Check that secret name was qualified
	//
	assert.Equal(t, "namespace/name/validation_context", resources.Secrets[0].Name)
}

var ciliumEnvoyConfigInvalid = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-prometheus-metrics-listener
    address:
      socket_address:
        address: 127.0.0.1
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          rds:
            route_config_name: local_route
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`

func TestCiliumEnvoyConfigValidation(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigInvalid))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.NotNil(t, cec.Spec.Resources)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, false)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/envoy-prometheus-metrics-listener", resources.Listeners[0].Name)
	assert.Equal(t, uint32(0), resources.Listeners[0].Address.GetSocketAddress().GetPortValue()) // invalid listener port number
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)

	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	assert.NotNil(t, rds)
	assert.Equal(t, "namespace/name/local_route", rds.RouteConfigName)
	checkCiliumXDS(t, rds.GetConfigSource())

	//
	// Check that HTTP filters are parsed
	//
	assert.Len(t, hcm.HttpFilters, 1)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[0].Name)

	//
	// Same with validation fails
	//
	resources, err = parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	assert.Error(t, err)
}

var ciliumEnvoyConfigNoAddress = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-prometheus-metrics-listener
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: ingress_route
            virtual_hosts:
            - name: ingress_route
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: "envoy-ingress"
          codec_type: AUTO
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`

func TestCiliumEnvoyConfigNoAddress(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigNoAddress))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.NotNil(t, cec.Spec.Resources)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/envoy-prometheus-metrics-listener", resources.Listeners[0].Name)
	assert.NotNil(t, resources.Listeners[0].Address)
	assert.NotNil(t, resources.Listeners[0].Address.GetSocketAddress())
	assert.NotEqual(t, 0, resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 2)
	assert.Equal(t, "cilium.network", chain.Filters[0].Name)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[1].Name)
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)

	//
	// Check that missing RDS config source is automatically filled in
	//
	rc := hcm.GetRouteConfig()
	assert.NotNil(t, rc)
	vh := rc.GetVirtualHosts()
	assert.Len(t, vh, 1)
	routes := vh[0].GetRoutes()
	assert.Len(t, routes, 1)
	route := routes[0].GetRoute()
	assert.NotNil(t, route)
	assert.Equal(t, "namespace/name/envoy-ingress", route.GetCluster())

	//
	// Check that HTTP filters are parsed
	//
	assert.Len(t, hcm.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", hcm.HttpFilters[0].Name)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[1].Name)
}

var ciliumEnvoyConfigMulti = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: multi-resource-listener
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          codec_type: AUTO
          rds:
            route_config_name: local_route
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
  - "@type": type.googleapis.com/envoy.config.route.v3.RouteConfiguration
    name: local_route
    virtual_hosts:
    - name: local_service
      domains: ["*"]
      routes:
      - match: { prefix: "/" }
        route: { cluster: some_service }
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: some_service
    connect_timeout: 0.25s
    lb_policy: ROUND_ROBIN
    type: EDS
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        common_tls_context:
          tls_certificate_sds_secret_configs:
          - name: cilium-secrets/client-mtls
          validation_context_sds_secret_config:
            name: cilium-secrets/client-mtls
  - "@type": type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
    cluster_name: some_service
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: 127.0.0.1
              port_value: 1234
  - "@type": type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
    cluster_name: other_service
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            socket_address:
              address: "::"
              port_value: 5678
`

func TestCiliumEnvoyConfigMulti(t *testing.T) {
	parser := CECResourceParser{
		logger:                      hivetest.Logger(t),
		portAllocator:               NewMockPortAllocator(),
		defaultMaxConcurrentRetries: 128,
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigMulti))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 5)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/multi-resource-listener", resources.Listeners[0].Name)
	assert.Nil(t, resources.Listeners[0].GetInternalListener())
	assert.Equal(t, uint32(10000), resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)
	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	assert.NotNil(t, rds)
	assert.Equal(t, "namespace/name/local_route", rds.RouteConfigName)
	checkCiliumXDS(t, rds.GetConfigSource())
	//
	// Check that HTTP filters are parsed
	//
	assert.Len(t, hcm.HttpFilters, 1)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[0].Name)

	//
	// Check route resource
	//
	assert.Equal(t, "type.googleapis.com/envoy.config.route.v3.RouteConfiguration", cec.Spec.Resources[1].TypeUrl)
	assert.Len(t, resources.Routes, 1)
	assert.Equal(t, "namespace/name/local_route", resources.Routes[0].Name)
	assert.Len(t, resources.Routes[0].VirtualHosts, 1)
	vh := resources.Routes[0].VirtualHosts[0]
	assert.Equal(t, "namespace/name/local_service", vh.Name)
	assert.Len(t, vh.Domains, 1)
	assert.Equal(t, "*", vh.Domains[0])
	assert.Len(t, vh.Routes, 1)
	assert.NotNil(t, vh.Routes[0].Match)
	assert.Equal(t, "/", vh.Routes[0].Match.GetPrefix())
	assert.NotNil(t, vh.Routes[0].GetRoute())
	assert.Equal(t, "namespace/name/some_service", vh.Routes[0].GetRoute().GetCluster())

	//
	// Check cluster resource
	//
	assert.Equal(t, "type.googleapis.com/envoy.config.cluster.v3.Cluster", cec.Spec.Resources[2].TypeUrl)
	assert.Len(t, resources.Clusters, 1)
	assert.Equal(t, "namespace/name/some_service", resources.Clusters[0].Name)
	assert.Equal(t, int64(0), resources.Clusters[0].ConnectTimeout.Seconds)
	assert.Equal(t, int32(250000000), resources.Clusters[0].ConnectTimeout.Nanos)
	assert.Equal(t, envoy_config_cluster.Cluster_ROUND_ROBIN, resources.Clusters[0].LbPolicy)
	assert.Equal(t, envoy_config_cluster.Cluster_EDS, resources.Clusters[0].GetType())
	//
	// Check that missing CircuitBreakers is automatically filled in
	//
	cb := resources.Clusters[0].CircuitBreakers
	assert.NotNil(t, cb)
	assert.Len(t, cb.Thresholds, 1)
	assert.Equal(t, uint32(128), cb.Thresholds[0].MaxRetries.Value)
	//
	// Check that missing EDS config source is automatically filled in
	//
	eds := resources.Clusters[0].GetEdsClusterConfig()
	assert.NotNil(t, eds)
	checkCiliumXDS(t, eds.GetEdsConfig())

	assert.NotNil(t, resources.Clusters[0].TransportSocket)
	assert.Equal(t, "envoy.transport_sockets.tls", resources.Clusters[0].TransportSocket.Name)
	msg, err := resources.Clusters[0].TransportSocket.GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, msg)
	tls, ok := msg.(*envoy_config_tls.UpstreamTlsContext)
	assert.True(t, ok)
	assert.NotNil(t, tls)
	//
	// Check that missing SDS config sources are automatically filled in
	//
	tlsContext := tls.CommonTlsContext
	assert.NotNil(t, tlsContext)
	for _, sc := range tlsContext.TlsCertificateSdsSecretConfigs {
		checkCiliumXDS(t, sc.SdsConfig)
	}
	sdsConfig := tlsContext.GetValidationContextSdsSecretConfig()
	assert.NotNil(t, sdsConfig)
	checkCiliumXDS(t, sdsConfig.SdsConfig)

	//
	// Check 1st endpoint resource
	//
	assert.Equal(t, "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", cec.Spec.Resources[3].TypeUrl)
	assert.Len(t, resources.Endpoints, 2)
	assert.Equal(t, "namespace/name/some_service", resources.Endpoints[0].ClusterName)
	assert.Len(t, resources.Endpoints[0].Endpoints, 1)
	assert.Len(t, resources.Endpoints[0].Endpoints[0].LbEndpoints, 1)
	addr := resources.Endpoints[0].Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	assert.NotNil(t, addr)
	assert.NotNil(t, addr.GetSocketAddress())
	assert.Equal(t, "127.0.0.1", addr.GetSocketAddress().GetAddress())
	assert.Equal(t, uint32(1234), addr.GetSocketAddress().GetPortValue())

	//
	// Check 2nd endpoint resource
	//
	assert.Equal(t, "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", cec.Spec.Resources[4].TypeUrl)
	assert.Len(t, resources.Endpoints, 2)
	assert.Equal(t, "namespace/name/other_service", resources.Endpoints[1].ClusterName)
	assert.Len(t, resources.Endpoints[1].Endpoints, 1)
	assert.Len(t, resources.Endpoints[1].Endpoints[0].LbEndpoints, 1)
	addr = resources.Endpoints[1].Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	assert.NotNil(t, addr)
	assert.NotNil(t, addr.GetSocketAddress())
	assert.Equal(t, "::", addr.GetSocketAddress().GetAddress())
	assert.Equal(t, uint32(5678), addr.GetSocketAddress().GetPortValue())
}

var ciliumEnvoyConfigTCPProxy = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-test-listener
spec:
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: tcp_proxy_test-2
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: "cluster_0"
          tunneling_config:
            hostname: host.com:443
            use_post: true
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: "cluster_0"
    connect_timeout: 5s
    # This ensures HTTP/2 POST is used for establishing the tunnel.
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: cluster_0
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 10001
`

var ciliumEnvoyConfigInternalListener = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: missing-internal-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
    cluster_name: internal_listener_cluster
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            envoy_internal_address:
              server_listener_name: internal-listener
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: internal-listener
    internal_listener: {}
`

func TestCiliumEnvoyConfigInternalListener(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigInternalListener))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 2)
	assert.Equal(t, "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", cec.Spec.Resources[0].TypeUrl)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[1].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	require.NoError(t, err)

	//
	// Check internal endpoint resource
	//
	assert.Len(t, resources.Endpoints, 1)
	assert.Equal(t, "namespace/name/internal_listener_cluster", resources.Endpoints[0].ClusterName)
	assert.Len(t, resources.Endpoints[0].Endpoints, 1)
	assert.Len(t, resources.Endpoints[0].Endpoints[0].LbEndpoints, 1)
	addr := resources.Endpoints[0].Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	assert.NotNil(t, addr)
	assert.NotNil(t, addr.GetEnvoyInternalAddress())
	assert.Equal(t, "namespace/name/internal-listener", addr.GetEnvoyInternalAddress().GetServerListenerName())

	//
	// Check internal listener
	//
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/internal-listener", resources.Listeners[0].Name)
	assert.NotNil(t, resources.Listeners[0].GetInternalListener())
}

var ciliumEnvoyConfigMissingInternalListener = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: missing-internal-listener
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment
    cluster_name: internal_listener_cluster
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            envoy_internal_address:
              server_listener_name: internal-listener
`

func TestCiliumEnvoyConfigMissingInternalListener(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigMissingInternalListener))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment", cec.Spec.Resources[0].TypeUrl)

	_, err = parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	assert.ErrorContains(t, err, "missing internal listener: internal-listener")
}

func TestCiliumEnvoyConfigTCPProxy(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigTCPProxy))
	require.NoError(t, err)

	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.NotNil(t, cec.Spec.Resources)
	assert.Len(t, cec.Spec.Resources, 2)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, true, true)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.NotNil(t, resources.Listeners[0].Address)
	assert.NotNil(t, resources.Listeners[0].Address.GetSocketAddress())
	assert.NotEqual(t, 0, resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	//
	// Check injected listener filter config
	//
	assert.Len(t, resources.Listeners[0].ListenerFilters, 1)
	assert.Equal(t, "cilium.bpf_metadata", resources.Listeners[0].ListenerFilters[0].Name)
	lfMsg, err := resources.Listeners[0].ListenerFilters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, lfMsg)
	lf, ok := lfMsg.(*cilium.BpfMetadata)
	assert.True(t, ok)
	assert.NotNil(t, lf)
	assert.False(t, lf.IsIngress)
	assert.True(t, lf.UseOriginalSourceAddress)
	assert.Equal(t, bpf.BPFFSRoot(), lf.BpfRoot)
	assert.False(t, lf.IsL7Lb)

	// TCP listener has no SO_LINGER config
	assert.Nil(t, lf.OriginalSourceSoLingerTime)

	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 2)
	assert.Equal(t, "cilium.network", chain.Filters[0].Name)
	assert.Equal(t, "envoy.filters.network.tcp_proxy", chain.Filters[1].Name)
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	tcp, ok := message.(*envoy_config_tcp.TcpProxy)
	assert.True(t, ok)
	assert.NotNil(t, tcp)
	//
	// Check TCP config
	//
	assert.Equal(t, "namespace/name/cluster_0", tcp.GetCluster())
	tc := tcp.GetTunnelingConfig()
	assert.NotNil(t, tc)
	assert.Equal(t, "host.com:443", tc.Hostname)
	assert.True(t, tc.UsePost)
	//
	// Check cluster resource
	//
	assert.Equal(t, "type.googleapis.com/envoy.config.cluster.v3.Cluster", cec.Spec.Resources[1].TypeUrl)
	assert.Len(t, resources.Clusters, 1)
	assert.Equal(t, "namespace/name/cluster_0", resources.Clusters[0].Name)
	assert.Equal(t, int64(5), resources.Clusters[0].ConnectTimeout.Seconds)
	assert.Equal(t, int32(0), resources.Clusters[0].ConnectTimeout.Nanos)
	assert.Equal(t, "namespace/name/cluster_0", resources.Clusters[0].LoadAssignment.ClusterName)
	assert.Len(t, resources.Clusters[0].LoadAssignment.Endpoints, 1)
	assert.Len(t, resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints, 1)
	addr := resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	assert.NotNil(t, addr)
	assert.NotNil(t, addr.GetSocketAddress())
	assert.Equal(t, "127.0.0.1", addr.GetSocketAddress().GetAddress())
	assert.Equal(t, uint32(10001), addr.GetSocketAddress().GetPortValue())
}

var ciliumEnvoyConfigTCPProxyTermination = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: tcp-proxy-ingress-listener
spec:
  services:
  - name: tcp-proxy-ingress
    namespace: cilium-test
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-ingress-listener
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: tcp-proxy-ingress-listener
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains:
              - "*"
              routes:
              - match:
                  prefix: "/"
                  headers:
                  - name: ":method"
                    string_match:
                      exact: "POST"
                route:
                  cluster: default/service_google
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config:
                      allow_post: true
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
          http2_protocol_options:
            allow_connect: true
  - "@type": type.googleapis.com/envoy.config.cluster.v3.Cluster
    name: default/service_google
    connect_timeout: 5s
    type: LOGICAL_DNS
    # Comment out the following line to test on v6 networks
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: default/service_google
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: www.google.com
                port_value: 443
`

func TestCiliumEnvoyConfigTCPProxyTermination(t *testing.T) {

	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigTCPProxyTermination))
	require.NoError(t, err)

	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.NotNil(t, cec.Spec.Resources)
	assert.Len(t, cec.Spec.Resources, 2)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, true, true, false, true)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.NotNil(t, resources.Listeners[0].Address)
	assert.NotNil(t, resources.Listeners[0].Address.GetSocketAddress())
	assert.NotEqual(t, 0, resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	//
	// Check injected listener filter config
	//
	assert.Len(t, resources.Listeners[0].ListenerFilters, 1)
	assert.Equal(t, "cilium.bpf_metadata", resources.Listeners[0].ListenerFilters[0].Name)
	lfMsg, err := resources.Listeners[0].ListenerFilters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, lfMsg)
	lf, ok := lfMsg.(*cilium.BpfMetadata)
	assert.True(t, ok)
	assert.NotNil(t, lf)
	assert.False(t, lf.IsIngress)
	assert.False(t, lf.UseOriginalSourceAddress)
	assert.Equal(t, bpf.BPFFSRoot(), lf.BpfRoot)
	assert.True(t, lf.IsL7Lb)

	// HTTP listener has zero SO_LINGER config
	assert.NotNil(t, lf.OriginalSourceSoLingerTime)
	assert.Zero(t, *lf.OriginalSourceSoLingerTime)

	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 2)
	assert.Equal(t, "cilium.network", chain.Filters[0].Name)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[1].Name)
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)
	//
	// Check HTTP config
	//
	assert.Len(t, hcm.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", hcm.HttpFilters[0].Name)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[1].Name)
	assert.Equal(t, "namespace/name/local_route", hcm.GetRouteConfig().Name)
	assert.Equal(t, "namespace/name/local_service", hcm.GetRouteConfig().VirtualHosts[0].Name)
	assert.Equal(t, "default/service_google", hcm.GetRouteConfig().VirtualHosts[0].Routes[0].GetRoute().GetCluster())
	//
	// Check cluster resource
	//
	assert.Equal(t, "type.googleapis.com/envoy.config.cluster.v3.Cluster", cec.Spec.Resources[1].TypeUrl)
	assert.Len(t, resources.Clusters, 1)
	assert.Equal(t, "default/service_google", resources.Clusters[0].Name)
	assert.Equal(t, int64(5), resources.Clusters[0].ConnectTimeout.Seconds)
	assert.Equal(t, int32(0), resources.Clusters[0].ConnectTimeout.Nanos)
	assert.Equal(t, envoy_config_cluster.Cluster_LOGICAL_DNS, resources.Clusters[0].GetType())
	assert.Equal(t, envoy_config_cluster.Cluster_V4_ONLY, resources.Clusters[0].GetDnsLookupFamily())
	assert.Equal(t, envoy_config_cluster.Cluster_ROUND_ROBIN, resources.Clusters[0].LbPolicy)

	assert.Equal(t, "default/service_google", resources.Clusters[0].LoadAssignment.ClusterName)
	assert.Len(t, resources.Clusters[0].LoadAssignment.Endpoints, 1)
	assert.Len(t, resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints, 1)
	addr := resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	assert.NotNil(t, addr)
	assert.NotNil(t, addr.GetSocketAddress())
	assert.Equal(t, "www.google.com", addr.GetSocketAddress().GetAddress())
	assert.Equal(t, uint32(443), addr.GetSocketAddress().GetPortValue())
	//
	// Check upstream filters (injected for L7 LB)
	//
	assert.NotNil(t, resources.Clusters[0].TypedExtensionProtocolOptions)
	assert.NotNil(t, resources.Clusters[0].TypedExtensionProtocolOptions[httpProtocolOptionsType])
	opts := &envoy_upstreams_http_v3.HttpProtocolOptions{}
	assert.NoError(t, resources.Clusters[0].TypedExtensionProtocolOptions[httpProtocolOptionsType].UnmarshalTo(opts))
	assert.NotNil(t, opts.HttpFilters)
	assert.Equal(t, "cilium.l7policy", opts.HttpFilters[0].Name)
	assert.Equal(t, ciliumL7FilterTypeURL, opts.HttpFilters[0].GetTypedConfig().TypeUrl)
	assert.Equal(t, "envoy.filters.http.upstream_codec", opts.HttpFilters[1].Name)
	assert.Equal(t, upstreamCodecFilterTypeURL, opts.HttpFilters[1].GetTypedConfig().TypeUrl)
}

func checkCiliumXDS(t *testing.T, cs *envoy_config_core.ConfigSource) {
	require.NotNil(t, cs)
	assert.Equal(t, envoy_config_core.ApiVersion_V3, cs.ResourceApiVersion)
	assert.Equal(t, int64(30), cs.InitialFetchTimeout.Seconds)
	acs := cs.GetApiConfigSource()
	assert.NotNil(t, acs)
	assert.Equal(t, envoy_config_core.ApiConfigSource_GRPC, acs.ApiType)
	assert.Equal(t, envoy_config_core.ApiVersion_V3, acs.TransportApiVersion)
	assert.True(t, acs.SetNodeOnFirstMessageOnly)
	assert.Len(t, acs.GrpcServices, 1)
	eg := acs.GrpcServices[0].GetEnvoyGrpc()
	assert.NotNil(t, eg)
	assert.Equal(t, "xds-grpc-cilium", eg.ClusterName)
}

var ciliumEnvoyConfigWithHealthFilter = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  namespace: test-namespace
  name: test-name
spec:
  resources:
  - '@type': type.googleapis.com/envoy.config.listener.v3.Listener
    name: listener
    address:
      socketAddress:
        address: 100.64.0.100
        portValue: 80
    filterChains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typedConfig:
          '@type': type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          httpFilters:
          - name: envoy.filters.http.health_check
            typedConfig:
              '@type': type.googleapis.com/envoy.extensions.filters.http.health_check.v3.HealthCheck
              clusterMinHealthyPercentages:
                cluster:
                  value: 20
              passThroughMode: false`

func TestCiliumEnvoyConfigtHTTPHealthCheckFilter(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigWithHealthFilter))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)

	resources, err := parser.ParseResources(cec.Namespace, cec.Name, cec.Spec.Resources, false, false, false, false)
	require.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)

	hcmMessage, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, hcmMessage)

	assert.IsType(t, &envoy_config_http.HttpConnectionManager{}, hcmMessage)
	pm, err := hcmMessage.(*envoy_config_http.HttpConnectionManager).HttpFilters[0].GetTypedConfig().UnmarshalNew()
	assert.NoError(t, err)

	assert.IsType(t, &envoy_config_http_healthcheck.HealthCheck{}, pm)
	assert.Len(t, pm.(*envoy_config_http_healthcheck.HealthCheck).ClusterMinHealthyPercentages, 1)
	assert.Contains(t, pm.(*envoy_config_http_healthcheck.HealthCheck).ClusterMinHealthyPercentages, "test-namespace/test-name/cluster")
}

func TestListenersAddedOrDeleted(t *testing.T) {
	var old envoy.Resources
	var new envoy.Resources

	// Both empty
	res := old.ListenersAddedOrDeleted(&new)
	assert.False(t, res)

	// new adds a listener
	new.Listeners = append(old.Listeners, &envoy_config_listener.Listener{Name: "foo"})
	res = old.ListenersAddedOrDeleted(&new)
	assert.True(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.True(t, res)

	// Now both have 'foo'
	old.Listeners = append(old.Listeners, &envoy_config_listener.Listener{Name: "foo"})
	res = old.ListenersAddedOrDeleted(&new)
	assert.False(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.False(t, res)

	// New has no listeners
	new.Listeners = nil
	res = old.ListenersAddedOrDeleted(&new)
	assert.True(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.True(t, res)

	// New has a different listener
	new.Listeners = append(new.Listeners, &envoy_config_listener.Listener{Name: "bar"})
	res = old.ListenersAddedOrDeleted(&new)
	assert.True(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.True(t, res)

	// New adds the listener in old, but still has the other listener
	new.Listeners = append(new.Listeners, &envoy_config_listener.Listener{Name: "foo"})
	res = old.ListenersAddedOrDeleted(&new)
	assert.True(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.True(t, res)

	// Same listeners but in different order
	old.Listeners = append(old.Listeners, &envoy_config_listener.Listener{Name: "bar"})
	res = old.ListenersAddedOrDeleted(&new)
	assert.False(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.False(t, res)

	// Old has no listeners
	old.Listeners = nil
	res = old.ListenersAddedOrDeleted(&new)
	assert.True(t, res)
	res = new.ListenersAddedOrDeleted(&old)
	assert.True(t, res)
}

var ciliumEnvoyConfigCombinedValidationContext = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: combined-validationcontext
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: combined-validationcontext
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          rds:
            route_config_name: local_route
          http_filters:
          - name: envoy.filters.http.router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          common_tls_context:
            combined_validation_context:
              default_validation_context:
                match_typed_subject_alt_names:
                - san_type: DNS
                  matcher:
                    exact: "api.example.com"
              validation_context_sds_secret_config:
                name: validation_context
`

func TestCiliumEnvoyConfigCombinedValidationContext(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigCombinedValidationContext))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	require.NoError(t, err)

	require.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/combined-validationcontext", resources.Listeners[0].Name)
	assert.Equal(t, uint32(10000), resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]

	assert.NotNil(t, chain.TransportSocket)
	assert.Equal(t, "envoy.transport_sockets.tls", chain.TransportSocket.Name)
	msg, err := chain.TransportSocket.GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, msg)
	tls, ok := msg.(*envoy_config_tls.DownstreamTlsContext)
	assert.True(t, ok)
	assert.NotNil(t, tls)

	//
	// Check that missing SDS config sources are automatically filled in
	//
	tlsContext := tls.CommonTlsContext

	cvc := tlsContext.GetCombinedValidationContext()

	sdsConfig := cvc.GetValidationContextSdsSecretConfig()
	assert.NotNil(t, sdsConfig)
	checkCiliumXDS(t, sdsConfig.SdsConfig)
	// Check that secret name was qualified
	assert.Equal(t, "namespace/name/validation_context", sdsConfig.Name)

	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)
}

var ciliumEnvoyConfigTlsSessionTicketKeys = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: sessionticket-keys
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: sessionticket-keys
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          rds:
            route_config_name: local_route
          http_filters:
          - name: envoy.filters.http.router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          require_client_certificate: true
          session_ticket_keys_sds_secret_config:
            name: sessionticketkeys
`

func TestCiliumEnvoyConfigTlsSessionTicketKeys(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigTlsSessionTicketKeys))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, false, false, false, true)
	require.NoError(t, err)

	require.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/sessionticket-keys", resources.Listeners[0].Name)
	assert.Equal(t, uint32(10000), resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]

	assert.NotNil(t, chain.TransportSocket)
	assert.Equal(t, "envoy.transport_sockets.tls", chain.TransportSocket.Name)
	msg, err := chain.TransportSocket.GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, msg)
	tls, ok := msg.(*envoy_config_tls.DownstreamTlsContext)
	assert.True(t, ok)
	assert.NotNil(t, tls)

	//
	// Check that missing SDS config sources are automatically filled in
	//
	sdsConfig := tls.GetSessionTicketKeysSdsSecretConfig()
	assert.NotNil(t, sdsConfig)
	checkCiliumXDS(t, sdsConfig.SdsConfig)
	// Check that secret name was qualified
	assert.Equal(t, "namespace/name/sessionticketkeys", sdsConfig.Name)

	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)
}

var ciliumEnvoyConfigInjectCiliumFilters = `apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: without-cilium-filters
spec:
  version_info: "0"
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: without-cilium-filters
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          rds:
            route_config_name: local_route
          http_filters:
          - name: envoy.filters.http.router
`

func TestCiliumEnvoyConfigInjectCiliumFilters(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigInjectCiliumFilters))
	require.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	require.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)

	resources, err := parser.ParseResources("namespace", "name", cec.Spec.Resources, true, false, false, true)
	require.NoError(t, err)

	require.Len(t, resources.Listeners, 1)
	assert.Equal(t, "namespace/name/without-cilium-filters", resources.Listeners[0].Name)
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	chain := resources.Listeners[0].FilterChains[0]

	//
	// Check that missing Cilium Envoy filters are not automatically filled in
	//

	// No Cilium network filter injected
	require.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	require.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)

	// No Cilium L7 filter injected
	require.Len(t, hcm.HttpFilters, 1)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[0].Name)
}

var envoySpec = []byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: envoy-prometheus-metrics-listener
    address:
      socket_address:
        address: "::"
        ipv4_compat: true
        port_value: 10000
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: envoy-prometheus-metrics-listener
          route_config:
            virtual_hosts:
            - name: "prometheus_metrics_route"
              domains: ["*"]
              routes:
              - match:
                  path: "/metrics"
                route:
                  cluster: "/envoy-admin"
                  prefix_rewrite: "/stats/prometheus"
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`)

func TestParseEnvoySpec(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON(envoySpec)
	assert.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	assert.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)
	assert.True(t, UseOriginalSourceAddress(&cec.ObjectMeta))

	resources, err := parser.ParseResources("", "name", cec.Spec.Resources, len(cec.Spec.Services) > 0, InjectCiliumEnvoyFilters(&cec.ObjectMeta, &cec.Spec), UseOriginalSourceAddress(&cec.ObjectMeta), true)
	assert.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, uint32(10000), resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	assert.Equal(t, "/name/envoy-prometheus-metrics-listener", resources.Listeners[0].Name)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 1)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[0].Name)
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	assert.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)
	rc := hcm.GetRouteConfig()
	assert.NotNil(t, rc)
	vh := rc.VirtualHosts
	assert.Len(t, vh, 1)
	assert.Equal(t, "/name/prometheus_metrics_route", vh[0].Name)
	assert.Len(t, vh[0].Routes, 1)
	assert.Equal(t, "/metrics", vh[0].Routes[0].Match.GetPath())
	assert.Equal(t, "/envoy-admin", vh[0].Routes[0].GetRoute().GetCluster())
	assert.Equal(t, "/stats/prometheus", vh[0].Routes[0].GetRoute().GetPrefixRewrite())
	assert.Len(t, hcm.HttpFilters, 1)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[0].Name)
}

var envoySpecWithService = []byte(`apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: l7-lb
  namespace: cilium-test
spec:
  services:
  - name: echo-other-node
    namespace: cilium-test
    ports: [8080, 9090]
  resources:
  - "@type": type.googleapis.com/envoy.config.listener.v3.Listener
    name: l7-lb
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: l7-lb
          codec_type: AUTO
          rds:
            route_config_name: l7-lb_route
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`)

func TestParseEnvoySpecWithService(t *testing.T) {
	parser := CECResourceParser{
		logger:        hivetest.Logger(t),
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON(envoySpecWithService)
	assert.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	assert.NoError(t, err)
	assert.Len(t, cec.Spec.Services, 1)
	assert.Equal(t, "echo-other-node", cec.Spec.Services[0].Name)
	assert.Equal(t, "cilium-test", cec.Spec.Services[0].Namespace)
	assert.Len(t, cec.Spec.Services[0].Ports, 2)
	assert.Equal(t, uint16(8080), cec.Spec.Services[0].Ports[0])
	assert.Equal(t, uint16(9090), cec.Spec.Services[0].Ports[1])

	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)
	assert.True(t, UseOriginalSourceAddress(&cec.ObjectMeta))

	resources, err := parser.ParseResources("", "name", cec.Spec.Resources, len(cec.Spec.Services) > 0, InjectCiliumEnvoyFilters(&cec.ObjectMeta, &cec.Spec), UseOriginalSourceAddress(&cec.ObjectMeta), true)
	assert.NoError(t, err)
	assert.Len(t, resources.Listeners, 1)
	assert.Equal(t, uint32(1025), resources.Listeners[0].Address.GetSocketAddress().GetPortValue())
	assert.Len(t, resources.Listeners[0].FilterChains, 1)
	assert.Equal(t, "/name/l7-lb", resources.Listeners[0].Name)
	chain := resources.Listeners[0].FilterChains[0]
	assert.Len(t, chain.Filters, 2)
	assert.Equal(t, "cilium.network", chain.Filters[0].Name)
	assert.Equal(t, "envoy.filters.network.http_connection_manager", chain.Filters[1].Name)
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	assert.NoError(t, err)
	assert.NotNil(t, message)
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	assert.True(t, ok)
	assert.NotNil(t, hcm)
	rc := hcm.GetRouteConfig()
	assert.Nil(t, rc)
	rds := hcm.GetRds()
	assert.NotNil(t, rds)
	assert.Equal(t, "/name/l7-lb_route", rds.GetRouteConfigName())
	assert.Len(t, hcm.HttpFilters, 2)
	assert.Equal(t, "cilium.l7policy", hcm.HttpFilters[0].Name)
	assert.Equal(t, "envoy.filters.http.router", hcm.HttpFilters[1].Name)
}

func TestIsCiliumIngress(t *testing.T) {
	// Non-ingress CEC
	jsonBytes, err := yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: envoy-prometheus-metrics-listener
spec:
  resources:
`))
	assert.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	assert.NoError(t, err)
	assert.True(t, UseOriginalSourceAddress(&cec.ObjectMeta))

	// Gateway API CCEC
	jsonBytes, err = yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideEnvoyConfig
metadata:
  name: cilium-gateway-all-namespaces
  ownerReferences:
  - apiVersion: gateway.networking.k8s.io/v1beta1
    kind: Gateway
    name: all-namespaces
    uid: bf4481cd-5d34-4880-93ec-76ddb34ab8a0
spec:
  resources:
`))
	assert.NoError(t, err)
	ccec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, ccec)
	assert.NoError(t, err)
	assert.False(t, UseOriginalSourceAddress(&ccec.ObjectMeta))

	// Ingress CEC
	jsonBytes, err = yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
metadata:
  name: cilium-ingress
  namespace: default
  ownerReferences:
  - apiVersion: networking.k8s.io/v1
    kind: Ingress
    name: basic-ingress
    namespace: default
spec:
  resources:
`))
	assert.NoError(t, err)
	cec = &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	assert.NoError(t, err)
	assert.False(t, UseOriginalSourceAddress(&cec.ObjectMeta))

	// CCEC with unknown owner kind
	jsonBytes, err = yaml.YAMLToJSON([]byte(`apiVersion: cilium.io/v2
kind: CiliumClusterwideEnvoyConfig
metadata:
  name: cilium-ingress
  ownerReferences:
  - apiVersion: example.io/v1
    kind: Monitoring
    name: test-monitor
spec:
  resources:
`))
	assert.NoError(t, err)
	ccec = &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, ccec)
	assert.NoError(t, err)
	assert.True(t, UseOriginalSourceAddress(&ccec.ObjectMeta))
}

func Test_injectCiliumEnvoyFilters(t *testing.T) {
	tests := []struct {
		name string
		meta *metav1.ObjectMeta
		spec *cilium_v2.CiliumEnvoyConfigSpec
		want bool
	}{
		{
			name: "L7LB services defined",
			meta: &metav1.ObjectMeta{},
			spec: &cilium_v2.CiliumEnvoyConfigSpec{
				Services: []*cilium_v2.ServiceListener{{
					Name: "test",
				}},
			},
			want: true,
		},
		{
			name: "L7LB services defined but override via annotation",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					annotation.CECInjectCiliumFilters: "false",
				},
			},
			spec: &cilium_v2.CiliumEnvoyConfigSpec{
				Services: []*cilium_v2.ServiceListener{{
					Name: "test",
				}},
			},
			want: false,
		},
		{
			name: "No L7LB services but explicit inject via annotation",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					annotation.CECInjectCiliumFilters: "true",
				},
			},
			spec: &cilium_v2.CiliumEnvoyConfigSpec{
				Services: []*cilium_v2.ServiceListener{},
			},
			want: true,
		},
		{
			name: "L7LB services defined and invalid annotation value",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					annotation.CECInjectCiliumFilters: "invalid",
				},
			},
			spec: &cilium_v2.CiliumEnvoyConfigSpec{
				Services: []*cilium_v2.ServiceListener{{
					Name: "test",
				}},
			},
			want: true,
		},
		{
			name: "No L7LB services and invalid annotation value",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{
					annotation.CECInjectCiliumFilters: "invalid",
				},
			},
			spec: &cilium_v2.CiliumEnvoyConfigSpec{
				Services: []*cilium_v2.ServiceListener{},
			},
			want: false,
		},
		{
			name: "No L7LB services and no annotation",
			meta: &metav1.ObjectMeta{
				Annotations: map[string]string{},
			},
			spec: &cilium_v2.CiliumEnvoyConfigSpec{
				Services: []*cilium_v2.ServiceListener{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InjectCiliumEnvoyFilters(tt.meta, tt.spec)
			assert.Equal(t, tt.want, got)
		})
	}
}
