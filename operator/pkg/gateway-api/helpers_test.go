// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
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
			route:    &gatewayv1alpha2.TLSRoute{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isKindAllowed(listener, tt.route))
		})
	}
}
