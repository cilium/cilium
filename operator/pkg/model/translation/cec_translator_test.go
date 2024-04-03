// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"slices"
	"testing"

	envoy_config_cluster_v3 "github.com/cilium/proxy/go/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_config_listener "github.com/cilium/proxy/go/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	envoy_http_connection_manager_v3 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_transport_sockets_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	matcherv3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

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
			i := &cecTranslator{}
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
	tests := []struct {
		name   string
		fields fields
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
			i := &cecTranslator{}
			got := i.getServices(tt.fields.namespace, tt.fields.name)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSharedIngressTranslator_getHTTPRouteListenerProxy(t *testing.T) {
	i := &cecTranslator{
		secretsNamespace: "cilium-secrets",
		useProxyProtocol: true,
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

	listenerNames := []string{}
	for _, l := range listener.ListenerFilters {
		listenerNames = append(listenerNames, l.Name)
	}
	slices.Sort(listenerNames)
	require.Equal(t, []string{proxyProtocolType, tlsInspectorType}, listenerNames)
}

func TestSharedIngressTranslator_getHTTPRouteListener(t *testing.T) {
	i := &cecTranslator{
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
	require.Nil(t, downStreamTLS.CommonTlsContext.TlsCertificateSdsSecretConfigs[0].GetSdsConfig())
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
				"random-namespace:default-backend:8080",
			},
		},
		{
			name: "host rule listeners",
			args: args{
				m: hostRulesModel,
			},
			expected: []string{
				"random-namespace:foo-bar-com:http",
				"random-namespace:wildcard-foo-com:8080",
			},
		},
		{
			name: "path rule listeners",
			args: args{
				m: pathRulesModel,
			},
			expected: []string{
				"random-namespace:aaa-prefix:8080",
				"random-namespace:aaa-slash-bbb-prefix:8080",
				"random-namespace:aaa-slash-bbb-slash-prefix:8080",
				"random-namespace:foo-exact:8080",
				"random-namespace:foo-prefix:8080",
				"random-namespace:foo-slash-exact:8080",
			},
		},
		{
			name: "complex ingress",
			args: args{
				m: complexIngressModel,
			},
			expected: []string{
				"dummy-namespace:another-dummy-backend:8081",
				"dummy-namespace:default-backend:8080",
				"dummy-namespace:dummy-backend:8080",
			},
		},
	}

	for _, tt := range tests {
		i := &cecTranslator{}

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

func TestGetEnvoyHTTPRouteConfiguration_VirtualHostSorted(t *testing.T) {
	defT := &cecTranslator{}

	routes := []model.HTTPRoute{
		{
			Backends: []model.Backend{
				{
					Name:      "default-backend",
					Namespace: "random-namespace",
					Port: &model.BackendPort{
						Port: 8080,
					},
				},
			},
		},
	}

	l1 := []model.HTTPListener{
		{
			Port:                     443,
			Hostname:                 "foo.bar",
			ForceHTTPtoHTTPSRedirect: true,
			Routes:                   routes,
		},
		{
			Port:     443,
			Hostname: "bar.foo",
			Routes:   routes,
		},
	}

	l2 := []model.HTTPListener{
		{
			Port:     443,
			Hostname: "bar.foo",
			Routes:   routes,
		},
		{
			Port:                     443,
			Hostname:                 "foo.bar",
			ForceHTTPtoHTTPSRedirect: true,
			Routes:                   routes,
		},
	}

	res1 := defT.getEnvoyHTTPRouteConfiguration(&model.Model{HTTP: l1})
	res2 := defT.getEnvoyHTTPRouteConfiguration(&model.Model{HTTP: l2})

	diffOutput := cmp.Diff(res1, res2, protocmp.Transform())
	if len(diffOutput) != 0 {
		t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
	}

	// assert.Equal(t, res1, res2)
}

func TestSharedIngressTranslator_getEnvoyHTTPRouteConfiguration(t *testing.T) {
	type args struct {
		m *model.Model
	}

	tests := []struct {
		name                 string
		args                 args
		expectedRouteConfigs []*envoy_config_route_v3.RouteConfiguration
	}{
		{
			name: "default backend",
			args: args{
				m: defaultBackendModel,
			},
			expectedRouteConfigs: defaultBackendExpectedConfig,
		},
		{
			name: "host rule",
			args: args{
				m: hostRulesModel,
			},
			expectedRouteConfigs: hostRulesExpectedConfig,
		},
		{
			name: "host rule with enforceHTTPS",
			args: args{
				m: hostRulesModelEnforcedHTTPS,
			},
			expectedRouteConfigs: hostRulesExpectedConfigEnforceHTTPS,
		},
		{
			name: "path rules",
			args: args{
				m: pathRulesModel,
			},
			expectedRouteConfigs: pathRulesExpectedConfig,
		},
		{
			name: "complex ingress",
			args: args{
				m: complexIngressModel,
			},
			expectedRouteConfigs: complexIngressExpectedConfig,
		},
		{
			name: "complex ingress with enforceHTTPS",
			args: args{
				m: complexIngressModelwithRedirects,
			},
			expectedRouteConfigs: complexIngressExpectedConfigEnforceHTTPS,
		},
		{
			name: "multiple path types in one listener",
			args: args{
				m: multiplePathTypesModel,
			},
			expectedRouteConfigs: multiplePathTypesExpectedConfig,
		},
		{
			name: "routes with multiple hostnames in one listener",
			args: args{
				m: multipleRouteHostnamesModel,
			},
			expectedRouteConfigs: multipleRouteHostnamesExpectedConfig,
		},
	}

	defT := &cecTranslator{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := defT.getEnvoyHTTPRouteConfiguration(tt.args.m)
			require.Len(t, res, len(tt.expectedRouteConfigs), "Number of Listeners did not match")

			for i, rawRoute := range res {
				ttListener := tt.expectedRouteConfigs[i]
				listener := &envoy_config_route_v3.RouteConfiguration{}
				err := proto.Unmarshal(rawRoute.Value, listener)
				require.NoError(t, err)

				for j, vhost := range listener.VirtualHosts {
					if j >= len(ttListener.VirtualHosts) {
						t.Errorf("More VirtualHosts in the actual than the expected for actual Listener name %s", listener.Name)
						continue
					}

					ttVhost := ttListener.VirtualHosts[j]

					if len(ttVhost.Routes) > len(vhost.Routes) {
						diffOutput := cmp.Diff(ttVhost.Routes, vhost.Routes, protocmp.Transform())
						t.Errorf("More Routes in the actual than the expected for actual VirtualHost name %s in actual Listener %s\n%s\n", vhost.Name, listener.Name, diffOutput)
					}

					for k, route := range vhost.Routes {
						if k >= len(ttVhost.Routes) {
							continue
						}

						ttRoute := ttVhost.Routes[k]

						diffOutput := cmp.Diff(ttRoute, route, protocmp.Transform())
						if len(diffOutput) != 0 {
							t.Errorf("Routes did not match for Listener %s and VirtualHost %s, route number %d:\n%s\n", ttListener.Name, ttVhost.Name, k, diffOutput)
						}
					}
					// If there were no errors at the Route level, check for errors at the VirtualHost level
					if !t.Failed() {
						diffOutput := cmp.Diff(ttVhost, vhost, protocmp.Transform())
						if len(diffOutput) != 0 {
							t.Errorf("VirtualHosts did not match for Listener %s:\n %s\n", listener.Name, diffOutput)
						}
					}
				}
				// If there were no errors anywhere else, check for errors at the Listener level
				if !t.Failed() {
					diffOutput := cmp.Diff(ttListener, listener, protocmp.Transform())
					if len(diffOutput) != 0 {
						t.Errorf("VirtualHosts did not match:\n %s\n", diffOutput)
					}
				}

			}
		})
	}
}

// The following helpers generate various types of path matches.
// Most notably, we treat a match for the path "/" differently to other matches,
// so it has its own helper.

func envoyRouteMatchExactPath(path string) *envoy_config_route_v3.RouteMatch {
	return &envoy_config_route_v3.RouteMatch{
		PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
			Path: path,
		},
	}
}

func envoyRouteMatchImplementationSpecific(path string) *envoy_config_route_v3.RouteMatch {
	return &envoy_config_route_v3.RouteMatch{
		PathSpecifier: &envoy_config_route_v3.RouteMatch_SafeRegex{
			SafeRegex: &matcherv3.RegexMatcher{
				Regex: path,
			},
		},
	}
}

func envoyRouteMatchRootPath() *envoy_config_route_v3.RouteMatch {
	return &envoy_config_route_v3.RouteMatch{
		PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
			Prefix: "/",
		},
	}
}

func envoyRouteMatchPrefixPath(path string) *envoy_config_route_v3.RouteMatch {
	return &envoy_config_route_v3.RouteMatch{
		PathSpecifier: &envoy_config_route_v3.RouteMatch_PathSeparatedPrefix{
			PathSeparatedPrefix: path,
		},
	}
}

func envoyRouteAction(namespace, backend, port string) *envoy_config_route_v3.Route_Route {
	return &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
				Cluster: fmt.Sprintf("%s:%s:%s", namespace, backend, port),
			},
		},
	}
}

func envoyHTTPSRouteRedirect() *envoy_config_route_v3.Route_Redirect {
	return &envoy_config_route_v3.Route_Redirect{
		Redirect: &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
				HttpsRedirect: true,
			},
		},
	}
}

func withAuthority(match *envoy_config_route_v3.RouteMatch, regex string) *envoy_config_route_v3.RouteMatch {
	authorityHeader := &envoy_config_route_v3.HeaderMatcher{
		Name: ":authority",
		HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
			StringMatch: &matcherv3.StringMatcher{
				MatchPattern: &matcherv3.StringMatcher_SafeRegex{
					SafeRegex: &matcherv3.RegexMatcher{
						Regex: regex,
					},
				},
			},
		},
	}

	match.Headers = append(match.Headers, authorityHeader)

	return match
}

func domainsHelper(domain string) []string {
	if domain == "*" {
		return []string{domain}
	}

	return []string{domain, fmt.Sprintf("%s:*", domain)}
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
			i := &cecTranslator{}
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
