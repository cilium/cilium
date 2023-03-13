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
			name: "Conformance/HTTPRouteListenerHostnameMatching",
			args: args{
				m: &model.Model{
					HTTP: listenerHostnameMatchingHTTPListeners,
				},
			},
			want: listenerHostNameMatchingCiliumEnvoyConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &translator{}
			cec, _, _, err := trans.Translate(tt.args.m)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			require.Equal(t, tt.want, cec, "CiliumEnvoyConfig did not match")
		})
	}
}
