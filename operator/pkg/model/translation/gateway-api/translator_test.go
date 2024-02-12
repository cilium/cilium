// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func Test_translator_Translate(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name    string
		args    args
		want    *ciliumv2.CiliumEnvoyConfig
		wantErr bool
	}{
		{
			name: "Basic HTTP Listener",
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(80),
				},
			},
			want: basicHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Basic TLS SNI Listener",
			args: args{
				m: &model.Model{
					TLS: basicTLSListeners,
				},
			},
			want: basicTLSListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteSimpleSameNamespace",
			args: args{
				m: &model.Model{
					HTTP: simpleSameNamespaceHTTPListeners,
				},
			},
			want: simpleSameNamespaceHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteCrossNamespace",
			args: args{
				m: &model.Model{
					HTTP: crossNamespaceHTTPListeners,
				},
			},
			want: crossNamespaceHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPExactPathMatching",
			args: args{
				m: &model.Model{
					HTTP: exactPathMatchingHTTPListeners,
				},
			},
			want: exactPathMatchingHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteHeaderMatching",
			args: args{
				m: &model.Model{
					HTTP: headerMatchingHTTPListeners,
				},
			},
			want: headerMatchingHTTPCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteHostnameIntersection",
			args: args{
				m: &model.Model{
					HTTP: hostnameIntersectionHTTPListeners,
				},
			},
			want: hostnameIntersectionHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteListenerHostnameMatching",
			args: args{
				m: &model.Model{
					HTTP: listenerHostnameMatchingHTTPListeners,
				},
			},
			want: listenerHostNameMatchingCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteMatchingAcrossRoutes",
			args: args{
				m: &model.Model{
					HTTP: matchingAcrossHTTPListeners,
				},
			},
			want: matchingAcrossHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteMatching",
			args: args{
				m: &model.Model{
					HTTP: matchingHTTPListeners,
				},
			},
			want: matchingHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteMethodMatching",
			args: args{
				m: &model.Model{
					HTTP: methodMatchingHTTPListeners,
				},
			},
			want: methodMatchingHTTPListenersHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteQueryParamMatching",
			args: args{
				m: &model.Model{
					HTTP: queryParamMatchingHTTPListeners,
				},
			},
			want: queryParamMatchingHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteRequestHeaderModifier",
			args: args{
				m: &model.Model{
					HTTP: requestHeaderModifierHTTPListeners,
				},
			},
			want: requestHeaderModifierHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteBackendRefsRequestHeaderModifier",
			args: args{
				m: &model.Model{
					HTTP: backendRefsRequestHeaderModifierHTTPListeners,
				},
			},
			want: backendRefsRequestHeaderModifierHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteRequestRedirect",
			args: args{
				m: &model.Model{
					HTTP: requestRedirectHTTPListeners,
				},
			},
			want: requestRedirectHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteResponseHeaderModifier",
			args: args{
				m: &model.Model{
					HTTP: responseHeaderModifierHTTPListeners,
				},
			},
			want: responseHeaderModifierHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteBackendRefsResponseHeaderModifier",
			args: args{
				m: &model.Model{
					HTTP: backendRefsResponseHeaderModifierHTTPListeners,
				},
			},
			want: backendRefsResponseHeaderModifierHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteRewriteHost",
			args: args{
				m: &model.Model{
					HTTP: rewriteHostHTTPListeners,
				},
			},
			want: rewriteHostHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteRewritePath",
			args: args{
				m: &model.Model{
					HTTP: rewritePathHTTPListeners,
				},
			},
			want: rewritePathHTTPListenersCiliumEnvoyConfig,
		},
		{
			name: "Conformance/HTTPRouteRequestMirror",
			args: args{
				m: &model.Model{
					HTTP: mirrorHTTPListeners,
				},
			},
			want: mirrorHTTPListenersCiliumEnvoyConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, true, 60, false, false, false),
			}
			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			require.Equal(t, tt.want, cec, "CiliumEnvoyConfig did not match")
		})
	}
}

func Test_translator_TranslateResource(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name          string
		args          args
		wantErr       bool
		validateFuncs []func(config *ciliumv2.CiliumEnvoyConfig) bool
	}{
		{
			name: "MultipleListenerGateway",
			args: args{
				m: &model.Model{
					HTTP: multipleListenerGatewayListeners,
				},
			},
			validateFuncs: []func(cec *ciliumv2.CiliumEnvoyConfig) bool{
				func(cec *ciliumv2.CiliumEnvoyConfig) bool {
					resource := ciliumv2.XDSResource{
						Any: toAny(&envoy_config_route_v3.RouteConfiguration{
							Name: "listener-insecure",
							VirtualHosts: []*envoy_config_route_v3.VirtualHost{
								{
									Name: "example.com",
									Domains: []string{
										"example.com",
										"example.com:*",
									},
									Routes: []*envoy_config_route_v3.Route{
										{
											Match: &envoy_config_route_v3.RouteMatch{
												PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
													Prefix: "/",
												},
											},
											Action: &envoy_config_route_v3.Route_Redirect{
												Redirect: &envoy_config_route_v3.RedirectAction{
													SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_SchemeRedirect{
														SchemeRedirect: "https",
													},
													PortRedirect: 443,
												},
											},
										},
									},
								},
							},
						}),
					}

					expected, _ := resource.MarshalJSON()
					got, _ := cec.Spec.Resources[1].MarshalJSON()
					return assert.Equal(t, string(expected), string(got), "Route Configuration mismatch")
				},
				func(cec *ciliumv2.CiliumEnvoyConfig) bool {
					resource := ciliumv2.XDSResource{
						Any: toAny(&envoy_config_route_v3.RouteConfiguration{
							Name: "listener-secure",
							VirtualHosts: []*envoy_config_route_v3.VirtualHost{
								{
									Name: "example.com",
									Domains: []string{
										"example.com",
										"example.com:*",
									},
									Routes: []*envoy_config_route_v3.Route{
										{
											Match: &envoy_config_route_v3.RouteMatch{
												PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
													Prefix: "/",
												},
											},
											Action: toRouteAction("default", "my-service", "8080"),
										},
									},
								},
							},
						}),
					}

					expected, _ := resource.MarshalJSON()
					got, _ := cec.Spec.Resources[2].MarshalJSON()
					return assert.Equal(t, string(expected), string(got), "Route Configuration mismatch")
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, true, 60, false, false, false),
			}
			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			for _, fn := range tt.validateFuncs {
				require.True(t, fn(cec), "Validation failed")
			}
		})
	}
}

func Test_translator_Translate_HostNetwork(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name        string
		args        args
		ipv4Enabled bool
		ipv6Enabled bool
		want        *ciliumv2.CiliumEnvoyConfig
		wantErr     bool
	}{
		{
			name:        "Basic HTTP Listener",
			ipv4Enabled: true,
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(80),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("0.0.0.0", 80),
		},
		{
			name:        "Basic HTTP Listener with different port",
			ipv4Enabled: true,
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(55555),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("0.0.0.0", 55555),
		},
		{
			name:        "Basic HTTP Listener with different port and IPv6",
			ipv4Enabled: false,
			ipv6Enabled: true,
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(55555),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("::", 55555),
		},
		{
			name:        "Basic HTTP Listener with LabelSelector",
			ipv4Enabled: true,
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(55555),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("0.0.0.0", 55555),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator:      translation.NewCECTranslator("cilium-secrets", false, true, 60, true, tt.ipv4Enabled, tt.ipv6Enabled),
				hostNetworkEnabled: true,
			}
			cec, svc, ep, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")

			diffOutput := cmp.Diff(tt.want, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}

			require.NotNil(t, svc)
			assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)

			require.NotNil(t, ep)
		})
	}
}
