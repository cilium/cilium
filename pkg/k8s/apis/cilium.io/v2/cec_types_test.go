// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	_ "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
)

var (
	envoySpec = []byte(`resources:
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
)

func TestParseEnvoySpec(t *testing.T) {
	// option.Config.Debug = true
	// logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	jsonBytes, err := yaml.YAMLToJSON([]byte(envoySpec))
	require.NoError(t, err)
	cec := &CiliumEnvoyConfig{}
	err = json.Unmarshal(jsonBytes, &cec.Spec)
	require.NoError(t, err)
	require.Len(t, cec.Spec.Resources, 1)
	require.Equal(t, "type.googleapis.com/envoy.config.listener.v3.Listener", cec.Spec.Resources[0].TypeUrl)
}
