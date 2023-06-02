// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

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
