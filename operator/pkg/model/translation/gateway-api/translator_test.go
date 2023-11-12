// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/model"
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
					HTTP: basicHTTPListeners,
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
			trans := &translator{
				idleTimeoutSeconds: 60,
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
			trans := &translator{
				idleTimeoutSeconds: 60,
			}
			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			for _, fn := range tt.validateFuncs {
				require.True(t, fn(cec), "Validation failed")
			}
		})
	}
}
