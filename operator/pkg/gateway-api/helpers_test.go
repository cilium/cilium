// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_isKindAllowed(t *testing.T) {
	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		Port:     443,
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Kinds: []gatewayv1.RouteGroupKind{
				{
					Group: GroupPtr(gatewayv1.GroupName),
					Kind:  kindHTTPRoute,
				},
				{
					Group: GroupPtr(gatewayv1.GroupName),
					Kind:  kindGRPCRoute,
				},
			},
		},
	}

	tests := []struct {
		name     string
		route    metav1.Object
		expected bool
	}{
		{
			name:     "HTTPRoute is allowed",
			route:    &gatewayv1.HTTPRoute{},
			expected: true,
		},
		{
			name:     "GRPCRoute is allowed",
			route:    &gatewayv1.GRPCRoute{},
			expected: true,
		},
		{
			name:     "TLSRoute is not allowed",
			route:    &gatewayv1.TLSRoute{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isKindAllowed(listener, tt.route))
		})
	}
}

func Test_isAllowed(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, gatewayv1.Install(scheme))
	assert.NoError(t, corev1.AddToScheme(scheme))

	logger := slog.New(slog.DiscardHandler)

	tests := []struct {
		name  string
		gw    *gatewayv1.Gateway
		route metav1.Object
		c     client.Client
		want  bool
	}{
		{
			name: "nil AllowedRoutes listener rejects cross-namespace route, later All listener allows",
			gw: gatewayWithListeners(
				listener("same-namespace", nil),
				listener("all", allowedRoutes(gatewayv1.NamespacesFromAll)),
			),
			route: testHTTPRoute("cross-ns"),
			c:     fake.NewClientBuilder().WithScheme(scheme).Build(),
			want:  true,
		},
		{
			name: "nil AllowedRoutes Namespaces listener rejects cross-namespace route, later All listener allows",
			gw: gatewayWithListeners(
				listener("same-namespace", &gatewayv1.AllowedRoutes{}),
				listener("all", allowedRoutes(gatewayv1.NamespacesFromAll)),
			),
			route: testHTTPRoute("cross-ns"),
			c:     fake.NewClientBuilder().WithScheme(scheme).Build(),
			want:  true,
		},
		{
			name: "selector listener does not match route namespace, later All listener allows",
			gw: gatewayWithListeners(
				listener("selector", selectorAllowedRoutes("allowed", "true")),
				listener("all", allowedRoutes(gatewayv1.NamespacesFromAll)),
			),
			route: testHTTPRoute("cross-ns"),
			c: fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(namespace("other-ns", map[string]string{"allowed": "true"})).
				Build(),
			want: true,
		},
		{
			name: "selector listener list error, later All listener allows",
			gw: gatewayWithListeners(
				listener("selector", selectorAllowedRoutes("allowed", "true")),
				listener("all", allowedRoutes(gatewayv1.NamespacesFromAll)),
			),
			route: testHTTPRoute("cross-ns"),
			c: namespaceListErrorClient{
				Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
			},
			want: true,
		},
		{
			name: "same-namespace default listener allows same-namespace route",
			gw: gatewayWithListeners(
				listener("same-namespace", nil),
			),
			route: testHTTPRoute("default"),
			c:     fake.NewClientBuilder().WithScheme(scheme).Build(),
			want:  true,
		},
		{
			name: "only same-namespace default listener rejects cross-namespace route",
			gw: gatewayWithListeners(
				listener("same-namespace", nil),
			),
			route: testHTTPRoute("cross-ns"),
			c:     fake.NewClientBuilder().WithScheme(scheme).Build(),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAllowed(context.Background(), tt.c, tt.gw, tt.route, logger))
		})
	}
}

type namespaceListErrorClient struct {
	client.Client
}

func (c namespaceListErrorClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.NamespaceList); ok {
		return errors.New("unable to list namespaces")
	}
	return c.Client.List(ctx, list, opts...)
}

func gatewayWithListeners(listeners ...gatewayv1.Listener) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners:        listeners,
		},
	}
}

func listener(name gatewayv1.SectionName, allowedRoutes *gatewayv1.AllowedRoutes) gatewayv1.Listener {
	return gatewayv1.Listener{
		Name:          name,
		Protocol:      gatewayv1.HTTPProtocolType,
		Port:          80,
		AllowedRoutes: allowedRoutes,
	}
}

func allowedRoutes(from gatewayv1.FromNamespaces) *gatewayv1.AllowedRoutes {
	return &gatewayv1.AllowedRoutes{
		Namespaces: &gatewayv1.RouteNamespaces{
			From: ptr.To(from),
		},
	}
}

func selectorAllowedRoutes(key, value string) *gatewayv1.AllowedRoutes {
	return &gatewayv1.AllowedRoutes{
		Namespaces: &gatewayv1.RouteNamespaces{
			From: ptr.To(gatewayv1.NamespacesFromSelector),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					key: value,
				},
			},
		},
	}
}

func testHTTPRoute(namespace string) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
	}
}

func namespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}
