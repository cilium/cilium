// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestIsListenerSet(t *testing.T) {
	tests := []struct {
		name string
		ref  gatewayv1.ParentReference
		want bool
	}{
		{
			name: "default kind (nil) is Gateway, not ListenerSet",
			ref:  gatewayv1.ParentReference{},
			want: false,
		},
		{
			name: "explicit Gateway kind",
			ref: gatewayv1.ParentReference{
				Kind: ptr.To[gatewayv1.Kind]("Gateway"),
			},
			want: false,
		},
		{
			name: "ListenerSet kind with default group",
			ref: gatewayv1.ParentReference{
				Kind: ptr.To[gatewayv1.Kind]("ListenerSet"),
			},
			want: true,
		},
		{
			name: "ListenerSet kind with explicit gateway-api group",
			ref: gatewayv1.ParentReference{
				Kind:  ptr.To[gatewayv1.Kind]("ListenerSet"),
				Group: ptr.To[gatewayv1.Group](gatewayv1.GroupName),
			},
			want: true,
		},
		{
			name: "ListenerSet kind with wrong group",
			ref: gatewayv1.ParentReference{
				Kind:  ptr.To[gatewayv1.Kind]("ListenerSet"),
				Group: ptr.To[gatewayv1.Group]("example.com"),
			},
			want: false,
		},
		{
			name: "Service kind",
			ref: gatewayv1.ParentReference{
				Kind:  ptr.To[gatewayv1.Kind]("Service"),
				Group: ptr.To[gatewayv1.Group](""),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsListenerSet(tt.ref))
		})
	}
}

func TestListenerEntryToListener(t *testing.T) {
	entry := gatewayv1.ListenerEntry{
		Name:     "https",
		Hostname: ptr.To[gatewayv1.Hostname]("example.com"),
		Port:     443,
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.ListenerTLSConfig{
			Mode: ptr.To(gatewayv1.TLSModeTerminate),
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: "my-cert"},
			},
		},
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Namespaces: &gatewayv1.RouteNamespaces{
				From: ptr.To(gatewayv1.NamespacesFromAll),
			},
		},
	}

	l := ListenerEntryToListener(entry)

	assert.Equal(t, entry.Name, l.Name)
	assert.Equal(t, entry.Hostname, l.Hostname)
	assert.Equal(t, entry.Port, l.Port)
	assert.Equal(t, entry.Protocol, l.Protocol)
	assert.Equal(t, entry.TLS, l.TLS)
	assert.Equal(t, entry.AllowedRoutes, l.AllowedRoutes)
}

func TestListenerSetParentGateway(t *testing.T) {
	tests := []struct {
		name          string
		ls            *gatewayv1.ListenerSet
		wantName      string
		wantNamespace string
	}{
		{
			name: "namespace defaults to ListenerSet namespace",
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ls-namespace",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name: "my-gateway",
					},
				},
			},
			wantName:      "my-gateway",
			wantNamespace: "ls-namespace",
		},
		{
			name: "explicit namespace in parentRef",
			ls: &gatewayv1.ListenerSet{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ls-namespace",
				},
				Spec: gatewayv1.ListenerSetSpec{
					ParentRef: gatewayv1.ParentGatewayReference{
						Name:      "my-gateway",
						Namespace: ptr.To[gatewayv1.Namespace]("gw-namespace"),
					},
				},
			},
			wantName:      "my-gateway",
			wantNamespace: "gw-namespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ListenerSetParentGateway(tt.ls)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantName, result.Name)
			assert.Equal(t, tt.wantNamespace, result.Namespace)
		})
	}
}
