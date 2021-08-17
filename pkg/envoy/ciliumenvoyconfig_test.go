// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package envoy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"

	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"

	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"

	. "gopkg.in/check.v1"
)

type JSONSuite struct{}

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
        http_filters:
        - name: envoy.filters.http.router
`

func (s *JSONSuite) TestCiliumEnvoyConfigSpec(c *C) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(xds1))
	c.Assert(err, IsNil)

	spec := cilium_v2alpha1.CiliumEnvoyConfigSpec{}
	err = json.Unmarshal(jsonBytes, &spec)
	c.Assert(err, IsNil)

	c.Assert(spec.Resources, HasLen, 1)
	c.Assert(spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")
}

var ciliumEnvoyConfig = `apiVersion: cilium.io/v2alpha1
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
          http_filters:
          - name: envoy.filters.http.router
`

func (s *JSONSuite) TestCiliumEnvoyConfig(c *C) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(ciliumEnvoyConfig))
	c.Assert(err, IsNil)
	var buf bytes.Buffer
	json.Indent(&buf, jsonBytes, "", "\t")
	fmt.Printf("JSON spec:\n%s\n", buf.String())
	cec := &cilium_v2alpha1.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, Not(IsNil))
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := ParseResources("prefix", cec)
	c.Assert(err, IsNil)
	c.Assert(resources.Listeners, HasLen, 1)
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

	rc := hcm.GetRouteConfig()
	c.Assert(rc, Not(IsNil))
	vh := rc.VirtualHosts
	c.Assert(vh, HasLen, 1)
	c.Assert(vh[0].Name, Equals, "prometheus_metrics_route")
	c.Assert(vh[0].Routes, HasLen, 1)
	c.Assert(vh[0].Routes[0].Match.GetPath(), Equals, "/metrics")
	c.Assert(vh[0].Routes[0].GetRoute().GetCluster(), Equals, "envoy-admin")
	c.Assert(vh[0].Routes[0].GetRoute().GetPrefixRewrite(), Equals, "/stats/prometheus")

	//
	// Check that HTTP filters are parsed
	//
	c.Assert(hcm.HttpFilters, HasLen, 1)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "envoy.filters.http.router")
}
