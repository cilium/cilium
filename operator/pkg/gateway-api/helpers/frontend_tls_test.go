// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestFrontendTLSConfigMapRefSet(t *testing.T) {
	tests := map[string]struct {
		gateway *gatewayv1.Gateway
		want    map[types.NamespacedName]struct{}
	}{
		"default validation": {
			gateway: gatewayWithFrontendTLSRefs([]gatewayv1.ObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				{Group: "", Kind: "ConfigMap", Name: "ignored-ca"},
			}, nil),
			want: map[types.NamespacedName]struct{}{
				{Namespace: "default", Name: "valid-ca"}: {},
			},
		},
		"per-port validation": {
			gateway: gatewayWithFrontendTLSRefs(nil, []gatewayv1.ObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "valid-ca"},
				{Group: "", Kind: "ConfigMap", Name: "ignored-ca"},
			}),
			want: map[types.NamespacedName]struct{}{
				{Namespace: "default", Name: "valid-ca"}: {},
			},
		},
		"no TLS validation": {
			gateway: gatewayWithFrontendTLSRefs(nil, nil),
			want:    map[types.NamespacedName]struct{}{},
		},
		"no frontend TLS config": {
			gateway: &gatewayv1.Gateway{},
			want:    nil,
		},
		"duplicate default and per-port references": {
			gateway: gatewayWithFrontendTLSRefs(
				[]gatewayv1.ObjectReference{{Group: "", Kind: "ConfigMap", Name: "client-ca"}},
				[]gatewayv1.ObjectReference{{Group: "", Kind: "ConfigMap", Name: "client-ca"}},
			),
			want: map[types.NamespacedName]struct{}{
				{Namespace: "default", Name: "client-ca"}: {},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tt.want, FrontendTLSConfigMapRefSet(tt.gateway))
		})
	}
}

func gatewayWithFrontendTLSRefs(defaultRefs, perPortRefs []gatewayv1.ObjectReference) *gatewayv1.Gateway {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gateway",
		},
		Spec: gatewayv1.GatewaySpec{
			TLS: &gatewayv1.GatewayTLSConfig{
				Frontend: &gatewayv1.FrontendTLSConfig{
					Default: gatewayv1.TLSConfig{},
				},
			},
		},
	}

	if defaultRefs != nil {
		gw.Spec.TLS.Frontend.Default.Validation = &gatewayv1.FrontendTLSValidation{
			CACertificateRefs: defaultRefs,
		}
	}
	if perPortRefs != nil {
		gw.Spec.TLS.Frontend.PerPort = []gatewayv1.TLSPortConfig{
			{
				Port: 443,
				TLS: gatewayv1.TLSConfig{
					Validation: &gatewayv1.FrontendTLSValidation{
						CACertificateRefs: perPortRefs,
					},
				},
			},
		}
	}

	return gw
}
