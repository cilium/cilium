// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

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
		{
			name: "Conformance/HTTPRouteRequestRedirectWithMultiHTTPListeners",
			args: args{
				m: &model.Model{
					HTTP: requestRedirectWithMultiHTTPListeners,
				},
			},
			want: requestRedirectWithMultiHTTPListenersCiliumEnvoyConfig,
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

func Test_getService(t *testing.T) {
	type args struct {
		resource    *model.FullyQualifiedResource
		allPorts    []uint32
		labels      map[string]string
		annotations map[string]string
	}
	tests := []struct {
		name string
		args args
		want *corev1.Service
	}{
		{
			name: "long name - more than 64 characters",
			args: args{
				resource: &model.FullyQualifiedResource{
					Name:      "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
					Namespace: "default",
					Version:   "v1",
					Kind:      "Gateway",
					UID:       "57889650-380b-4c05-9a2e-3baee7fd5271",
				},
				allPorts: []uint32{80},
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-long-long-long-long-long-long-lo-8tfth549c6",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel: "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1beta1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
							UID:        types.UID("57889650-380b-4c05-9a2e-3baee7fd5271"),
							Controller: model.AddressOf(true),
						},
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:     fmt.Sprintf("port-%d", 80),
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
					Type: corev1.ServiceTypeLoadBalancer,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getService(tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations)
			assert.Equalf(t, tt.want, got, "getService(%v, %v, %v, %v)", tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations)
			assert.Equal(t, true, len(got.Name) <= 63, "Service name is too long")
		})
	}
}
