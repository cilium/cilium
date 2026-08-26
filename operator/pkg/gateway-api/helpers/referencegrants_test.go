// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsReferenceAllowed(t *testing.T) {
	secretGVK := corev1.SchemeGroupVersion.WithKind("Secret")

	grantIn := func(namespace string, to gatewayv1.ReferenceGrantTo) gatewayv1.ReferenceGrant {
		return gatewayv1.ReferenceGrant{
			ObjectMeta: metav1.ObjectMeta{Name: "grant", Namespace: namespace},
			Spec: gatewayv1.ReferenceGrantSpec{
				From: []gatewayv1.ReferenceGrantFrom{{
					Group:     gatewayv1.GroupName,
					Kind:      "Gateway",
					Namespace: "gateway-ns",
				}},
				To: []gatewayv1.ReferenceGrantTo{to},
			},
		}
	}

	secretTo := gatewayv1.ReferenceGrantTo{Group: corev1.GroupName, Kind: "Secret"}

	tests := []struct {
		name                 string
		originatingNamespace string
		refName              string
		refNamespace         *gatewayv1.Namespace
		grants               []gatewayv1.ReferenceGrant
		want                 bool
	}{
		{
			name:                 "same namespace is allowed without a grant",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         nil,
			want:                 true,
		},
		{
			name:                 "explicit same namespace is allowed without a grant",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("gateway-ns"),
			want:                 true,
		},
		{
			name:                 "cross namespace is denied without a grant",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			want:                 false,
		},
		{
			name:                 "cross namespace is allowed by a matching grant",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			grants: []gatewayv1.ReferenceGrant{
				grantIn("secret-ns", gatewayv1.ReferenceGrantTo{
					Group: corev1.GroupName,
					Kind:  "Secret",
					Name:  ptr.To[gatewayv1.ObjectName]("tls-secret"),
				}),
			},
			want: true,
		},
		{
			name:                 "a grant without a name allows any name of that kind",
			originatingNamespace: "gateway-ns",
			refName:              "any-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			grants:               []gatewayv1.ReferenceGrant{grantIn("secret-ns", secretTo)},
			want:                 true,
		},
		{
			name:                 "a grant naming another object does not allow this one",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			grants: []gatewayv1.ReferenceGrant{
				grantIn("secret-ns", gatewayv1.ReferenceGrantTo{
					Group: corev1.GroupName,
					Kind:  "Secret",
					Name:  ptr.To[gatewayv1.ObjectName]("other-secret"),
				}),
			},
			want: false,
		},
		{
			name:                 "a grant in the wrong namespace does not apply",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			grants:               []gatewayv1.ReferenceGrant{grantIn("other-ns", secretTo)},
			want:                 false,
		},
		{
			name:                 "a grant for another target kind does not apply",
			originatingNamespace: "gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			grants: []gatewayv1.ReferenceGrant{
				grantIn("secret-ns", gatewayv1.ReferenceGrantTo{Group: corev1.GroupName, Kind: "ConfigMap"}),
			},
			want: false,
		},
		{
			name:                 "a grant from another source namespace does not apply",
			originatingNamespace: "other-gateway-ns",
			refName:              "tls-secret",
			refNamespace:         ptr.To[gatewayv1.Namespace]("secret-ns"),
			grants:               []gatewayv1.ReferenceGrant{grantIn("secret-ns", secretTo)},
			want:                 false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsReferenceAllowed(
				tt.originatingNamespace,
				tt.refName,
				tt.refNamespace,
				GatewayV1GVK("Gateway"),
				secretGVK,
				tt.grants,
			)
			require.Equal(t, tt.want, got)
		})
	}
}
