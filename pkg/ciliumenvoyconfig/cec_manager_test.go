// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"encoding/json"
	"io"
	"testing"

	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

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
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	parser := cecResourceParser{
		logger:        logger,
		portAllocator: NewMockPortAllocator(),
	}

	jsonBytes, err := yaml.YAMLToJSON(envoySpec)
	assert.NoError(t, err)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	assert.NoError(t, err)
	assert.Len(t, cec.Spec.Resources, 1)
	assert.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)
	assert.True(t, useOriginalSourceAddress(&cec.ObjectMeta))

	resources, err := parser.parseResources("", "name", cec.Spec.Resources, len(cec.Spec.Services) > 0, useOriginalSourceAddress(&cec.ObjectMeta), true)
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
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	parser := cecResourceParser{
		logger:        logger,
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
	assert.True(t, useOriginalSourceAddress(&cec.ObjectMeta))

	resources, err := parser.parseResources("", "name", cec.Spec.Resources, len(cec.Spec.Services) > 0, useOriginalSourceAddress(&cec.ObjectMeta), true)
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
	assert.True(t, useOriginalSourceAddress(&cec.ObjectMeta))

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
	assert.False(t, useOriginalSourceAddress(&ccec.ObjectMeta))

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
	assert.False(t, useOriginalSourceAddress(&cec.ObjectMeta))

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
	assert.True(t, useOriginalSourceAddress(&ccec.ObjectMeta))
}
