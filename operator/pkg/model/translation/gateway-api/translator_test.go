// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"testing"

	envoy_config_route_v3 "github.com/cilium/proxy/go/envoy/config/route/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
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
					TLSPassthrough: basicTLSListeners,
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
			name: "Conformance/HTTPRouteBackendProtocolH2C",
			args: args{
				m: &model.Model{
					HTTP: backendProtocolDisabledH2CHTTPListeners,
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
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, false, true, 60, false, nil, false, false, 0),
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
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, false, true, 60, false, nil, false, false, 0),
			}
			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			for _, fn := range tt.validateFuncs {
				require.True(t, fn(cec), "Validation failed")
			}
		})
	}
}

func Test_translator_Translate_AppProtocol(t *testing.T) {
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
			name: "Conformance/HTTPRouteBackendProtocolH2C",
			args: args{
				m: &model.Model{
					HTTP: backendProtocolEnabledH2CHTTPListeners,
				},
			},
			want: backendProtocolEnabledH2CHTTPListenersCiliumEnvoyConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator("cilium-secrets", false, true, true, 60, false, nil, false, false, 0),
			}
			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			require.Equal(t, tt.want, cec, "CiliumEnvoyConfig did not match")
		})
	}
}

func Test_translator_Translate_HostNetwork(t *testing.T) {
	type args struct {
		m *model.Model
	}
	tests := []struct {
		name              string
		args              args
		nodeLabelSelector *slim_metav1.LabelSelector
		ipv4Enabled       bool
		ipv6Enabled       bool
		want              *ciliumv2.CiliumEnvoyConfig
		wantErr           bool
	}{
		{
			name:        "Basic HTTP Listener",
			ipv4Enabled: true,
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(80),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("0.0.0.0", 80, nil),
		},
		{
			name:        "Basic HTTP Listener with different port",
			ipv4Enabled: true,
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(55555),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("0.0.0.0", 55555, nil),
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
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("::", 55555, nil),
		},
		{
			name:        "Basic HTTP Listener with LabelSelector",
			ipv4Enabled: true,
			nodeLabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"a": "b",
				},
			},
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(55555),
				},
			},
			want: basicHostPortHTTPListenersCiliumEnvoyConfig("0.0.0.0", 55555, &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{"a": "b"}}),
		},
	}
	for _, tt := range tests {
		translatorCases := []struct {
			name                 string
			gatewayAPITranslator *gatewayAPITranslator
		}{
			{
				name: "Without externalTrafficPolicy",
				gatewayAPITranslator: &gatewayAPITranslator{
					cecTranslator:      translation.NewCECTranslator("cilium-secrets", false, false, true, 60, true, tt.nodeLabelSelector, tt.ipv4Enabled, tt.ipv6Enabled, 0),
					hostNetworkEnabled: true,
				},
			},
			{
				name: "With externalTrafficPolicy",
				gatewayAPITranslator: &gatewayAPITranslator{
					cecTranslator:         translation.NewCECTranslator("cilium-secrets", false, false, true, 60, true, tt.nodeLabelSelector, tt.ipv4Enabled, tt.ipv6Enabled, 0),
					hostNetworkEnabled:    true,
					externalTrafficPolicy: "Cluster",
				},
			},
		}

		t.Run(tt.name, func(t *testing.T) {
			for _, translatorCase := range translatorCases {
				t.Run(translatorCase.name, func(t *testing.T) {
					cec, svc, ep, err := translatorCase.gatewayAPITranslator.Translate(tt.args.m)
					require.Equal(t, tt.wantErr, err != nil, "Error mismatch")

					diffOutput := cmp.Diff(tt.want, cec, protocmp.Transform())
					if len(diffOutput) != 0 {
						t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
					}

					require.NotNil(t, svc)
					assert.Equal(t, corev1.ServiceTypeClusterIP, svc.Spec.Type)
					require.Emptyf(t, svc.Spec.ExternalTrafficPolicy, "ClusterIP Services must not have an ExternalTrafficPolicy")

					require.NotNil(t, ep)
				})
			}
		})
	}
}

func Test_translator_Translate_WithXffNumTrustedHops(t *testing.T) {
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
			name: "Basic HTTP Listener with XffNumTrustedHops",
			args: args{
				m: &model.Model{
					HTTP: basicHTTPListeners(80),
				},
			},
			want: basicHTTPListenersCiliumEnvoyConfigWithXff,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{
				cecTranslator:      translation.NewCECTranslator("cilium-secrets", false, false, true, 60, false, nil, false, false, 2),
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

func Test_getService(t *testing.T) {
	type args struct {
		resource              *model.FullyQualifiedResource
		allPorts              []uint32
		labels                map[string]string
		annotations           map[string]string
		externalTrafficPolicy string
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
				allPorts:              []uint32{80},
				externalTrafficPolicy: "Cluster",
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-long-long-long-long-long-long-lo-8tfth549c6",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel:                       "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
						"gateway.networking.k8s.io/gateway-name": "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1beta1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
							UID:        types.UID("57889650-380b-4c05-9a2e-3baee7fd5271"),
							Controller: ptr.To(true),
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
					Type:                  corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
				},
			},
		},
		{
			name: "externaltrafficpolicy set to local",
			args: args{
				resource: &model.FullyQualifiedResource{
					Name:      "test-externaltrafficpolicy-local",
					Namespace: "default",
					Version:   "v1",
					Kind:      "Gateway",
					UID:       "41b82697-2d8d-4776-81b6-44d0bbac7faa",
				},
				allPorts:              []uint32{80},
				externalTrafficPolicy: "Local",
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-externaltrafficpolicy-local",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel:                       "test-externaltrafficpolicy-local",
						"gateway.networking.k8s.io/gateway-name": "test-externaltrafficpolicy-local",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1beta1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-externaltrafficpolicy-local",
							UID:        types.UID("41b82697-2d8d-4776-81b6-44d0bbac7faa"),
							Controller: ptr.To(true),
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
					Type:                  corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getService(tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations, tt.args.externalTrafficPolicy)
			assert.Equalf(t, tt.want, got, "getService(%v, %v, %v, %v)", tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations)
			assert.Equal(t, true, len(got.Name) <= 63, "Service name is too long")
		})
	}
}
