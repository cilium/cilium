// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"encoding/json"

	_ "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_http "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	"sigs.k8s.io/yaml"

	"github.com/cilium/cilium/pkg/envoy"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	. "github.com/cilium/checkmate"
)

var (
	envoySpec = []byte(`apiVersion: cilium.io/v2
kind: CiliumEnvoyConfig
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
                  cluster: "envoy-admin"
                  prefix_rewrite: "/stats/prometheus"
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: envoy.filters.http.router
`)
)

func (s *K8sWatcherSuite) TestParseEnvoySpec(c *C) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(envoySpec))
	c.Assert(err, IsNil)
	cec := &cilium_v2.CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, cec)
	c.Assert(err, IsNil)
	c.Assert(cec.Spec.Resources, HasLen, 1)
	c.Assert(cec.Spec.Resources[0].TypeUrl, Equals, "type.googleapis.com/envoy.config.listener.v3.Listener")

	resources, err := envoy.ParseResources("namespace", "name", cec.Spec.Resources, true, nil, len(cec.Spec.Services) > 0, !isIngressKind(&cec.ObjectMeta))
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
	c.Assert(hcm.HttpFilters, HasLen, 1)
	c.Assert(hcm.HttpFilters[0].Name, Equals, "envoy.filters.http.router")
}
