// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestSharedIngressTranslator_getBackendServices(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name string
		args args
		want []*ciliumv2.Service
	}{
		{
			name: "default backend listener",
			args: args{
				m: defaultBackendModel,
			},
			want: []*ciliumv2.Service{
				{
					Name:      "default-backend",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
			},
		},
		{
			name: "host rule listeners",
			args: args{
				m: hostRulesModel,
			},
			want: []*ciliumv2.Service{
				{
					Name:      "foo-bar-com",
					Namespace: "random-namespace",
					Ports: []string{
						"http",
					},
				},
				{
					Name:      "wildcard-foo-com",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
			},
		},
		{
			name: "path rule listeners",
			args: args{
				m: pathRulesModel,
			},
			want: []*ciliumv2.Service{
				{
					Name:      "aaa-prefix",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
				{
					Name:      "aaa-slash-bbb-prefix",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
				{
					Name:      "aaa-slash-bbb-slash-prefix",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
				{
					Name:      "foo-exact",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
				{
					Name:      "foo-prefix",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
				{
					Name:      "foo-slash-exact",
					Namespace: "random-namespace",
					Ports: []string{
						"8080",
					},
				},
			},
		},
		{
			name: "complex ingress",
			args: args{
				m: complexIngressModel,
			},
			want: []*ciliumv2.Service{
				{
					Name:      "another-dummy-backend",
					Namespace: "dummy-namespace",
					Ports:     []string{"8081"},
				},
				{
					Name:      "default-backend",
					Namespace: "dummy-namespace",
					Ports:     []string{"8080"},
				},
				{
					Name:      "dummy-backend",
					Namespace: "dummy-namespace",
					Ports:     []string{"8080"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &defaultTranslator{}
			res := i.getBackendServices(tt.args.m)
			require.Equal(t, tt.want, res)
		})
	}
}

func TestSharedIngressTranslator_getServices(t *testing.T) {
	type fields struct {
		name      string
		namespace string
	}
	type args struct {
		in0 *model.Model
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []*ciliumv2.ServiceListener
	}{
		{
			name: "default case",
			fields: fields{
				name:      "cilium-ingress",
				namespace: "kube-system",
			},
			want: []*ciliumv2.ServiceListener{
				{
					Name:      "cilium-ingress",
					Namespace: "kube-system",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &defaultTranslator{
				name:      tt.fields.name,
				namespace: tt.fields.namespace,
			}
			got := i.getServices(tt.args.in0)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSharedIngressTranslator_getHTTPRouteListener(t *testing.T) {
	i := &defaultTranslator{
		name:             "cilium-ingress",
		namespace:        "kube-system",
		secretsNamespace: "cilium-secrets",
	}

	res := i.getHTTPRouteListener(&model.Model{
		HTTP: []model.HTTPListener{
			{
				TLS: []model.TLSSecret{
					{
						Name:      "dummy-secret",
						Namespace: "dummy-namespace",
					},
				},
			},
		},
	})
	require.Len(t, res, 1)

	listener := &envoy_config_listener.Listener{}
	err := proto.Unmarshal(res[0].GetValue(), listener)
	require.NoError(t, err)

	require.Len(t, listener.ListenerFilters, 1)
	require.Len(t, listener.FilterChains, 2)
	require.Len(t, listener.FilterChains[0].Filters, 1)
	require.Len(t, listener.SocketOptions, 4)
	require.IsType(t, &envoy_config_listener.Filter_TypedConfig{}, listener.FilterChains[0].Filters[0].ConfigType)

	// check for connection manager
	insecureConnectionManager := &envoy_http_connection_manager_v3.HttpConnectionManager{}
	err = proto.Unmarshal(listener.FilterChains[0].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, insecureConnectionManager)
	require.NoError(t, err)

	require.Equal(t, "listener-insecure", insecureConnectionManager.StatPrefix)
	require.Equal(t, "listener-insecure", insecureConnectionManager.GetRds().RouteConfigName)

	secureConnectionManager := &envoy_http_connection_manager_v3.HttpConnectionManager{}
	err = proto.Unmarshal(listener.FilterChains[1].Filters[0].ConfigType.(*envoy_config_listener.Filter_TypedConfig).TypedConfig.Value, secureConnectionManager)
	require.NoError(t, err)

	require.Equal(t, "listener-secure", secureConnectionManager.StatPrefix)
	require.Equal(t, "listener-secure", secureConnectionManager.GetRds().RouteConfigName)

	// check TLS configuration
	require.Equal(t, "envoy.transport_sockets.tls", listener.FilterChains[1].TransportSocket.Name)
	require.IsType(t, &envoy_config_core_v3.TransportSocket_TypedConfig{}, listener.FilterChains[1].TransportSocket.ConfigType)

	downStreamTLS := &envoy_transport_sockets_tls_v3.DownstreamTlsContext{}
	err = proto.Unmarshal(listener.FilterChains[1].TransportSocket.ConfigType.(*envoy_config_core_v3.TransportSocket_TypedConfig).TypedConfig.Value, downStreamTLS)
	require.NoError(t, err)

	require.Len(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs, 1)
	require.Equal(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetName(), "cilium-secrets/dummy-namespace-dummy-secret")
	require.NotNil(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetSdsConfig())
}

func TestSharedIngressTranslator_getClusters(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name     string
		args     args
		expected []string
	}{
		{
			name: "default backend listener",
			args: args{
				m: defaultBackendModel,
			},
			expected: []string{
				"random-namespace/default-backend:8080",
			},
		},
		{
			name: "host rule listeners",
			args: args{
				m: hostRulesModel,
			},
			expected: []string{
				"random-namespace/foo-bar-com:http",
				"random-namespace/wildcard-foo-com:8080",
			},
		},
		{
			name: "path rule listeners",
			args: args{
				m: pathRulesModel,
			},
			expected: []string{
				"random-namespace/aaa-prefix:8080",
				"random-namespace/aaa-slash-bbb-prefix:8080",
				"random-namespace/aaa-slash-bbb-slash-prefix:8080",
				"random-namespace/foo-exact:8080",
				"random-namespace/foo-prefix:8080",
				"random-namespace/foo-slash-exact:8080",
			},
		},
		{
			name: "complex ingress",
			args: args{
				m: complexIngressModel,
			},
			expected: []string{
				"dummy-namespace/another-dummy-backend:8081",
				"dummy-namespace/default-backend:8080",
				"dummy-namespace/dummy-backend:8080",
			},
		},
	}

	for _, tt := range tests {
		i := &defaultTranslator{}

		t.Run(tt.name, func(t *testing.T) {
			res := i.getClusters(tt.args.m)
			require.Len(t, res, len(tt.expected))

			for i := 0; i < len(tt.expected); i++ {
				cluster := &envoy_config_cluster_v3.Cluster{}
				err := proto.Unmarshal(res[i].GetValue(), cluster)
				require.NoError(t, err)

				require.Equal(t, tt.expected[i], cluster.Name)
				require.Equal(t, &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_EDS}, cluster.ClusterDiscoveryType)
			}
		})
	}
}

func TestSharedIngressTranslator_getEnvoyHTTPRouteConfiguration(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name               string
		args               args
		expectedRouteVHMap map[string][]string
	}{
		{
			name: "default backend",
			args: args{
				m: defaultBackendModel,
			},
			expectedRouteVHMap: map[string][]string{
				"listener-insecure": {
					"*",
				},
			},
		},
		{
			name: "host rule",
			args: args{
				m: hostRulesModel,
			},
			expectedRouteVHMap: map[string][]string{
				"listener-insecure": {
					"*.foo.com",
					"foo.bar.com",
				},
				"listener-secure": {
					"foo.bar.com",
				},
			},
		},
		{
			name: "path rules",
			args: args{
				m: pathRulesModel,
			},
			expectedRouteVHMap: map[string][]string{
				"listener-insecure": {
					"exact-path-rules",
					"mixed-path-rules",
					"prefix-path-rules",
					"trailing-slash-path-rules",
				},
			},
		},
		{
			name: "complex ingress",
			args: args{
				m: complexIngressModel,
			},
			expectedRouteVHMap: map[string][]string{
				"listener-insecure": {
					"*",
				},
				"listener-secure": {
					"very-secure.server.com",
					"another-very-secure.server.com",
				},
			},
		},
	}

	i := &defaultTranslator{
		name:      "cilium-ingress",
		namespace: "kube-system",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := i.getEnvoyHTTPRouteConfiguration(tt.args.m)
			require.Len(t, res, len(tt.expectedRouteVHMap))

			for i := 0; i < len(tt.expectedRouteVHMap); i++ {
				route := &envoy_config_route_v3.RouteConfiguration{}
				err := proto.Unmarshal(res[i].GetValue(), route)
				require.NoError(t, err)
				require.Containsf(t, tt.expectedRouteVHMap, route.Name, "route name %s not found", route.Name)

				var names []string
				for _, vh := range route.VirtualHosts {
					names = append(names, vh.Name)
				}
				require.ElementsMatchf(t, tt.expectedRouteVHMap[route.Name], names, "virtual hosts for route %s do not match", route.Name)
			}
		})
	}
}

func TestSharedIngressTranslator_getResources(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name     string
		args     args
		expected int
	}{
		{
			name: "default backend",
			args: args{
				m: defaultBackendModel,
			},
			expected: 3,
		},
		{
			name: "host rules",
			args: args{
				m: hostRulesModel,
			},
			expected: 5,
		},
		{
			name: "path rules",
			args: args{
				m: pathRulesModel,
			},
			expected: 8,
		},
		{
			name: "complex ingress",
			args: args{
				m: complexIngressModel,
			},
			expected: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &defaultTranslator{
				name: "cilium-ingress",
			}
			got := i.getResources(tt.args.m)
			require.Lenf(t, got, tt.expected, "expected %d resources, got %d", tt.expected, len(got))

			// Log for debugging purpose
			for _, e := range got {
				b, _ := e.MarshalJSON()
				t.Logf("%s\n", b)
			}
		})
	}
}
