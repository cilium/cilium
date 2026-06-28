// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_frontendTLSConfigMapMatchesUsesOnlyFirstRef(t *testing.T) {
	cfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "first-ca",
		},
	}
	ignoredCfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ignored-ca",
		},
	}

	tests := map[string]struct {
		gateway *gatewayv1.Gateway
	}{
		"default validation": {
			gateway: gatewayWithFrontendTLSRefs([]gatewayv1.ObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "first-ca"},
				{Group: "", Kind: "ConfigMap", Name: "ignored-ca"},
			}, nil),
		},
		"per-port validation": {
			gateway: gatewayWithFrontendTLSRefs(nil, []gatewayv1.ObjectReference{
				{Group: "", Kind: "ConfigMap", Name: "first-ca"},
				{Group: "", Kind: "ConfigMap", Name: "ignored-ca"},
			}),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.True(t, frontendTLSConfigMapMatches(tt.gateway, cfgMap))
			require.False(t, frontendTLSConfigMapMatches(tt.gateway, ignoredCfgMap))
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
				Frontend: &gatewayv1.FrontendTLSConfig{},
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
