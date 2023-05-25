// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"encoding/json"
	"fmt"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tcp "github.com/cilium/proxy/go/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/bpf"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	. "github.com/cilium/checkmate"
)

type JSONSuite struct{}

type MockPort struct {
	port uint16
	cnt  int
}

type MockPortAllocator struct {
	port  uint16
	ports map[string]*MockPort
}

func NewMockPortAllocator() *MockPortAllocator {
	return &MockPortAllocator{
		port:  1024,
		ports: make(map[string]*MockPort),
	}
}

func (m *MockPortAllocator) AllocateProxyPort(name string, ingress, localOnly bool) (uint16, error) {
	if mp, exists := m.ports[name]; exists {
		return mp.port, nil
	}
	m.port++
	m.ports[name] = &MockPort{port: m.port}

	return m.port, nil
}

func (m *MockPortAllocator) AckProxyPort(ctx context.Context, name string) error {
	mp, exists := m.ports[name]
	if !exists {
		return fmt.Errorf("Non-allocated port %s", name)
	}
	mp.cnt++
	return nil
}

func (m *MockPortAllocator) ReleaseProxyPort(name string) error {
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

var _ = Suite(&JSONSuite{})

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
                cluster: "envoy-admin"
                prefix_rewrite: "/stats/prometheus"
        use_remote_address: true
        skip_xff_append: true
        http_filters:
        - name: envoy.filters.http.router
`

func (s *JSONSuite) TestCiliumEnvoyConfigSpec(c *C) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(xds1))
	c.Assert(err, IsNil)

	spec := cilium_v2.CiliumEnvoyConfigSpec{}
	err = json.Unmarshal(jsonBytes, &spec)
	c.Assert(err, IsNil)

	c.Assert(spec.Resources, HasLen, 1)
	c.Assert(spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")
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
              name: cilium-secrets/server-mtls
`

func (s *JSONSuite) TestCiliumEnvoyConfig(c *C) {
	portAllocator := NewMockPortAllocator()
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfig))
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, Not(IsNil))
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("namespace", "name", cec.Spec.Resources, true, portAllocator, false, false)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Name, Equals, "namespace/name/envoy-prometheus-metrics-listener")
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Equals, uint32(10000))
	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	chain := resources.Listeners[0].FilterChains[0]

	c.Assert(chain.TransportSocket, Not(IsNil))
	c.Assert(chain.TransportSocket.Name, Equals, "envoy.transport_sockets.tls")
	msg, err := chain.TransportSocket.GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(msg, Not(IsNil))
	tls, ok := msg.(*envoy_config_tls.DownstreamTlsContext)
	c.Assert(ok, Equals, true)
	c.Assert(tls, Not(IsNil))
	//
	// Check that missing SDS config sources are automatically filled in
	//
	tlsContext := tls.CommonTlsContext
	c.Assert(tlsContext, Not(IsNil))
	for _, sc := range tlsContext.TlsCertificateSdsSecretConfigs {
		checkCiliumXDS(c, sc.SdsConfig)
	}
	sdsConfig := tlsContext.GetValidationContextSdsSecretConfig()
	c.Assert(sdsConfig, Not(IsNil))
	checkCiliumXDS(c, sdsConfig.SdsConfig)

	c.Assert(chain.Filters, HasLen, 1)
	c.Assert(chain.Filters[0].Name, Equals, "envoy.filters.network.http_connection_manager")
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	c.Assert(ok, Equals, true)
	c.Assert(hcm, Not(IsNil))

	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	c.Assert(rds, Not(IsNil))
	c.Assert(rds.RouteConfigName, Equals, "namespace/name/local_route")
	checkCiliumXDS(c, rds.GetConfigSource())

	//
	// Check that HTTP filters are parsed
	//
	c.Assert(hcm.HttpFilters, HasLen, 1)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "envoy.filters.http.router")
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

func (s *JSONSuite) TestCiliumEnvoyConfigValidation(c *C) {
	portAllocator := NewMockPortAllocator()
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigInvalid))
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, Not(IsNil))
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("namespace", "name", cec.Spec.Resources, false, portAllocator, false, false)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Name, Equals, "namespace/name/envoy-prometheus-metrics-listener")
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Equals, uint32(0)) // invalid listener port number
	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	chain := resources.Listeners[0].FilterChains[0]
	c.Assert(chain.Filters, HasLen, 1)
	c.Assert(chain.Filters[0].Name, Equals, "envoy.filters.network.http_connection_manager")
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	c.Assert(ok, Equals, true)
	c.Assert(hcm, Not(IsNil))

	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	c.Assert(rds, Not(IsNil))
	c.Assert(rds.RouteConfigName, Equals, "namespace/name/local_route")
	checkCiliumXDS(c, rds.GetConfigSource())

	//
	// Check that HTTP filters are parsed
	//
	c.Assert(hcm.HttpFilters, HasLen, 1)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "envoy.filters.http.router")

	//
	// Same with validation fails
	//
	resources, err = ParseResources("namespace", "name", cec.Spec.Resources, true, portAllocator, false, false)
	c.Assert(err, Not(IsNil))
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
          codec_type: AUTO
          rds:
            route_config_name: local_route
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`

func (s *JSONSuite) TestCiliumEnvoyConfigNoAddress(c *C) {
	portAllocator := NewMockPortAllocator()
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigNoAddress))
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, Not(IsNil))
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("namespace", "name", cec.Spec.Resources, true, portAllocator, false, false)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Name, Equals, "namespace/name/envoy-prometheus-metrics-listener")
	c.Assert(resources.Listeners[0].Address, Not(IsNil))
	c.Assert(resources.Listeners[0].Address.GetSocketAddress(), Not(IsNil))
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Not(Equals), 0)
	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	chain := resources.Listeners[0].FilterChains[0]
	c.Assert(chain.Filters, HasLen, 2)
	c.Assert(chain.Filters[0].Name, Equals, "cilium.network")
	c.Assert(chain.Filters[1].Name, Equals, "envoy.filters.network.http_connection_manager")
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	c.Assert(ok, Equals, true)
	c.Assert(hcm, Not(IsNil))

	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	c.Assert(rds, Not(IsNil))
	c.Assert(rds.RouteConfigName, Equals, "namespace/name/local_route")
	checkCiliumXDS(c, rds.GetConfigSource())

	//
	// Check that HTTP filters are parsed
	//
	c.Assert(hcm.HttpFilters, HasLen, 2)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "cilium.l7policy")
	c.Assert(hcm.HttpFilters[1].Name, Equals, "envoy.filters.http.router")
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

func (s *JSONSuite) TestCiliumEnvoyConfigMulti(c *C) {
	portAllocator := NewMockPortAllocator()
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigMulti))
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, HasLen, 5)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("namespace", "name", cec.Spec.Resources, true, portAllocator, false, false)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Name, Equals, "namespace/name/multi-resource-listener")
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Equals, uint32(10000))
	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	chain := resources.Listeners[0].FilterChains[0]
	c.Assert(chain.Filters, HasLen, 1)
	c.Assert(chain.Filters[0].Name, Equals, "envoy.filters.network.http_connection_manager")
	message, err := chain.Filters[0].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	c.Assert(ok, Equals, true)
	c.Assert(hcm, Not(IsNil))
	//
	// Check that missing RDS config source is automatically filled in
	//
	rds := hcm.GetRds()
	c.Assert(rds, Not(IsNil))
	c.Assert(rds.RouteConfigName, Equals, "namespace/name/local_route")
	checkCiliumXDS(c, rds.GetConfigSource())
	//
	// Check that HTTP filters are parsed
	//
	c.Assert(hcm.HttpFilters, HasLen, 1)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "envoy.filters.http.router")

	//
	// Check route resource
	//
	c.Assert(cec.Spec.Resources[1].TypeUrl, Equals, "type.googleapis.com/envoy.config.route.v3.RouteConfiguration")
	c.Assert(resources.Routes, HasLen, 1)
	c.Assert(resources.Routes[0].Name, Equals, "namespace/name/local_route")
	c.Assert(resources.Routes[0].VirtualHosts, HasLen, 1)
	vh := resources.Routes[0].VirtualHosts[0]
	c.Assert(vh.Name, Equals, "local_service")
	c.Assert(vh.Domains, HasLen, 1)
	c.Assert(vh.Domains[0], Equals, "*")
	c.Assert(vh.Routes, HasLen, 1)
	c.Assert(vh.Routes[0].Match, Not(IsNil))
	c.Assert(vh.Routes[0].Match.GetPrefix(), Equals, "/")
	c.Assert(vh.Routes[0].GetRoute(), Not(IsNil))
	c.Assert(vh.Routes[0].GetRoute().GetCluster(), Equals, "some_service")

	//
	// Check cluster resource
	//
	c.Assert(cec.Spec.Resources[2].TypeUrl, Equals, "type.googleapis.com/envoy.config.cluster.v3.Cluster")
	c.Assert(resources.Clusters, HasLen, 1)
	c.Assert(resources.Clusters[0].Name, Equals, "some_service")
	c.Assert(resources.Clusters[0].ConnectTimeout.Seconds, Equals, int64(0))
	c.Assert(resources.Clusters[0].ConnectTimeout.Nanos, Equals, int32(250000000))
	c.Assert(resources.Clusters[0].LbPolicy, Equals, envoy_config_cluster.Cluster_ROUND_ROBIN)
	c.Assert(resources.Clusters[0].GetType(), Equals, envoy_config_cluster.Cluster_EDS)
	//
	// Check that missing EDS config source is automatically filled in
	//
	eds := resources.Clusters[0].GetEdsClusterConfig()
	c.Assert(eds, Not(IsNil))
	checkCiliumXDS(c, eds.GetEdsConfig())

	c.Assert(resources.Clusters[0].TransportSocket, Not(IsNil))
	c.Assert(resources.Clusters[0].TransportSocket.Name, Equals, "envoy.transport_sockets.tls")
	msg, err := resources.Clusters[0].TransportSocket.GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(msg, Not(IsNil))
	tls, ok := msg.(*envoy_config_tls.UpstreamTlsContext)
	c.Assert(ok, Equals, true)
	c.Assert(tls, Not(IsNil))
	//
	// Check that missing SDS config sources are automatically filled in
	//
	tlsContext := tls.CommonTlsContext
	c.Assert(tlsContext, Not(IsNil))
	for _, sc := range tlsContext.TlsCertificateSdsSecretConfigs {
		checkCiliumXDS(c, sc.SdsConfig)
	}
	sdsConfig := tlsContext.GetValidationContextSdsSecretConfig()
	c.Assert(sdsConfig, Not(IsNil))
	checkCiliumXDS(c, sdsConfig.SdsConfig)

	//
	// Check 1st endpoint resource
	//
	c.Assert(cec.Spec.Resources[3].TypeUrl, Equals, "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment")
	c.Assert(resources.Endpoints, HasLen, 2)
	c.Assert(resources.Endpoints[0].ClusterName, Equals, "some_service")
	c.Assert(resources.Endpoints[0].Endpoints, HasLen, 1)
	c.Assert(resources.Endpoints[0].Endpoints[0].LbEndpoints, HasLen, 1)
	addr := resources.Endpoints[0].Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	c.Assert(addr, Not(IsNil))
	c.Assert(addr.GetSocketAddress(), Not(IsNil))
	c.Assert(addr.GetSocketAddress().GetAddress(), Equals, "127.0.0.1")
	c.Assert(addr.GetSocketAddress().GetPortValue(), Equals, uint32(1234))

	//
	// Check 2nd endpoint resource
	//
	c.Assert(cec.Spec.Resources[4].TypeUrl, Equals, "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment")
	c.Assert(resources.Endpoints, HasLen, 2)
	c.Assert(resources.Endpoints[1].ClusterName, Equals, "other_service")
	c.Assert(resources.Endpoints[1].Endpoints, HasLen, 1)
	c.Assert(resources.Endpoints[1].Endpoints[0].LbEndpoints, HasLen, 1)
	addr = resources.Endpoints[1].Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	c.Assert(addr, Not(IsNil))
	c.Assert(addr.GetSocketAddress(), Not(IsNil))
	c.Assert(addr.GetSocketAddress().GetAddress(), Equals, "::")
	c.Assert(addr.GetSocketAddress().GetPortValue(), Equals, uint32(5678))
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

func (s *JSONSuite) TestCiliumEnvoyConfigTCPProxy(c *C) {
	portAllocator := NewMockPortAllocator()
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigTCPProxy))
	c.Assert(err, IsNil)

	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, Not(IsNil))
	c.Assert(cec.Spec.Resources, HasLen, 2)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("namespace", "name", cec.Spec.Resources, true, portAllocator, false, true)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Address, Not(IsNil))
	c.Assert(resources.Listeners[0].Address.GetSocketAddress(), Not(IsNil))
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Not(Equals), 0)
	//
	// Check injected listener filter config
	//
	c.Assert(resources.Listeners[0].ListenerFilters, HasLen, 1)
	c.Assert(resources.Listeners[0].ListenerFilters[0].Name, Equals, "cilium.bpf_metadata")
	lfMsg, err := resources.Listeners[0].ListenerFilters[0].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(lfMsg, Not(IsNil))
	lf, ok := lfMsg.(*cilium.BpfMetadata)
	c.Assert(ok, Equals, true)
	c.Assert(lf, Not(IsNil))
	c.Assert(lf.IsIngress, Equals, false)
	c.Assert(lf.UseOriginalSourceAddress, Equals, true)
	c.Assert(lf.BpfRoot, Equals, bpf.BPFFSRoot())
	c.Assert(lf.IsL7Lb, Equals, false)

	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	chain := resources.Listeners[0].FilterChains[0]
	c.Assert(chain.Filters, HasLen, 2)
	c.Assert(chain.Filters[0].Name, Equals, "cilium.network")
	c.Assert(chain.Filters[1].Name, Equals, "envoy.filters.network.tcp_proxy")
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	tcp, ok := message.(*envoy_config_tcp.TcpProxy)
	c.Assert(ok, Equals, true)
	c.Assert(tcp, Not(IsNil))
	//
	// Check TCP config
	//
	tc := tcp.GetTunnelingConfig()
	c.Assert(tc, Not(IsNil))
	c.Assert(tc.Hostname, Equals, "host.com:443")
	c.Assert(tc.UsePost, Equals, true)
	//
	// Check cluster resource
	//
	c.Assert(cec.Spec.Resources[1].TypeUrl, Equals, "type.googleapis.com/envoy.config.cluster.v3.Cluster")
	c.Assert(resources.Clusters, HasLen, 1)
	c.Assert(resources.Clusters[0].Name, Equals, "cluster_0")
	c.Assert(resources.Clusters[0].ConnectTimeout.Seconds, Equals, int64(5))
	c.Assert(resources.Clusters[0].ConnectTimeout.Nanos, Equals, int32(0))
	c.Assert(resources.Clusters[0].LoadAssignment.ClusterName, Equals, "cluster_0")
	c.Assert(resources.Clusters[0].LoadAssignment.Endpoints, HasLen, 1)
	c.Assert(resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints, HasLen, 1)
	addr := resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	c.Assert(addr, Not(IsNil))
	c.Assert(addr.GetSocketAddress(), Not(IsNil))
	c.Assert(addr.GetSocketAddress().GetAddress(), Equals, "127.0.0.1")
	c.Assert(addr.GetSocketAddress().GetPortValue(), Equals, uint32(10001))
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
                  cluster: service_google
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
    name: service_google
    connect_timeout: 5s
    type: LOGICAL_DNS
    # Comment out the following line to test on v6 networks
    dns_lookup_family: V4_ONLY
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: service_google
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: www.google.com
                port_value: 443
`

func (s *JSONSuite) TestCiliumEnvoyConfigTCPProxyTermination(c *C) {
	portAllocator := NewMockPortAllocator()
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfigTCPProxyTermination))
	c.Assert(err, IsNil)

	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, Not(IsNil))
	c.Assert(cec.Spec.Resources, HasLen, 2)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("namespace", "name", cec.Spec.Resources, true, portAllocator, true, false)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
	c.Assert(resources.Listeners[0].Address, Not(IsNil))
	c.Assert(resources.Listeners[0].Address.GetSocketAddress(), Not(IsNil))
	c.Assert(resources.Listeners[0].Address.GetSocketAddress().GetPortValue(), Not(Equals), 0)
	//
	// Check injected listener filter config
	//
	c.Assert(resources.Listeners[0].ListenerFilters, HasLen, 1)
	c.Assert(resources.Listeners[0].ListenerFilters[0].Name, Equals, "cilium.bpf_metadata")
	lfMsg, err := resources.Listeners[0].ListenerFilters[0].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(lfMsg, Not(IsNil))
	lf, ok := lfMsg.(*cilium.BpfMetadata)
	c.Assert(ok, Equals, true)
	c.Assert(lf, Not(IsNil))
	c.Assert(lf.IsIngress, Equals, false)
	c.Assert(lf.UseOriginalSourceAddress, Equals, false)
	c.Assert(lf.BpfRoot, Equals, bpf.BPFFSRoot())
	c.Assert(lf.IsL7Lb, Equals, true)

	c.Assert(resources.Listeners[0].FilterChains, HasLen, 1)
	chain := resources.Listeners[0].FilterChains[0]
	c.Assert(chain.Filters, HasLen, 2)
	c.Assert(chain.Filters[0].Name, Equals, "cilium.network")
	c.Assert(chain.Filters[1].Name, Equals, "envoy.filters.network.http_connection_manager")
	message, err := chain.Filters[1].GetTypedConfig().UnmarshalNew()
	c.Assert(err, IsNil)
	c.Assert(message, Not(IsNil))
	hcm, ok := message.(*envoy_config_http.HttpConnectionManager)
	c.Assert(ok, Equals, true)
	c.Assert(hcm, Not(IsNil))
	//
	// Check HTTP config
	//
	c.Assert(hcm.HttpFilters, HasLen, 2)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "cilium.l7policy")
	c.Assert(hcm.HttpFilters[1].Name, Equals, "envoy.filters.http.router")
	//
	// Check cluster resource
	//
	c.Assert(cec.Spec.Resources[1].TypeUrl, Equals, "type.googleapis.com/envoy.config.cluster.v3.Cluster")
	c.Assert(resources.Clusters, HasLen, 1)
	c.Assert(resources.Clusters[0].Name, Equals, "service_google")
	c.Assert(resources.Clusters[0].ConnectTimeout.Seconds, Equals, int64(5))
	c.Assert(resources.Clusters[0].ConnectTimeout.Nanos, Equals, int32(0))
	c.Assert(resources.Clusters[0].GetType(), Equals, envoy_config_cluster.Cluster_LOGICAL_DNS)
	c.Assert(resources.Clusters[0].GetDnsLookupFamily(), Equals, envoy_config_cluster.Cluster_V4_ONLY)
	c.Assert(resources.Clusters[0].LbPolicy, Equals, envoy_config_cluster.Cluster_ROUND_ROBIN)

	c.Assert(resources.Clusters[0].LoadAssignment.ClusterName, Equals, "service_google")
	c.Assert(resources.Clusters[0].LoadAssignment.Endpoints, HasLen, 1)
	c.Assert(resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints, HasLen, 1)
	addr := resources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address
	c.Assert(addr, Not(IsNil))
	c.Assert(addr.GetSocketAddress(), Not(IsNil))
	c.Assert(addr.GetSocketAddress().GetAddress(), Equals, "www.google.com")
	c.Assert(addr.GetSocketAddress().GetPortValue(), Equals, uint32(443))
}

func checkCiliumXDS(c *C, cs *envoy_config_core.ConfigSource) {
	c.Assert(cs, Not(IsNil))
	c.Assert(cs.ResourceApiVersion, Equals, envoy_config_core.ApiVersion_V3)
	acs := cs.GetApiConfigSource()
	c.Assert(acs, Not(IsNil))
	c.Assert(acs.ApiType, Equals, envoy_config_core.ApiConfigSource_GRPC)
	c.Assert(acs.TransportApiVersion, Equals, envoy_config_core.ApiVersion_V3)
	c.Assert(acs.SetNodeOnFirstMessageOnly, Equals, true)
	c.Assert(acs.GrpcServices, HasLen, 1)
	eg := acs.GrpcServices[0].GetEnvoyGrpc()
	c.Assert(eg, Not(IsNil))
	c.Assert(eg.ClusterName, Equals, "xds-grpc-cilium")
}

func (s *JSONSuite) TestListenersAddedOrDeleted(c *C) {
	var old Resources
	var new Resources

	// Both empty
	res := old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, false)

	// new adds a listener
	new.Listeners = append(old.Listeners, &envoy_config_listener.Listener{Name: "foo"})
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, true)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, true)

	// Now both have 'foo'
	old.Listeners = append(old.Listeners, &envoy_config_listener.Listener{Name: "foo"})
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, false)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, false)

	// New has no listeners
	new.Listeners = nil
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, true)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, true)

	// New has a different listener
	new.Listeners = append(new.Listeners, &envoy_config_listener.Listener{Name: "bar"})
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, true)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, true)

	// New adds the listener in old, but still has the other listener
	new.Listeners = append(new.Listeners, &envoy_config_listener.Listener{Name: "foo"})
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, true)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, true)

	// Same listeners but in different order
	old.Listeners = append(old.Listeners, &envoy_config_listener.Listener{Name: "bar"})
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, false)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, false)

	// Old has no listeners
	old.Listeners = nil
	res = old.ListenersAddedOrDeleted(&new)
	c.Assert(res, Equals, true)
	res = new.ListenersAddedOrDeleted(&old)
	c.Assert(res, Equals, true)
}
