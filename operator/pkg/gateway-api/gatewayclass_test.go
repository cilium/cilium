// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

func Test_matchesControllerName(t *testing.T) {
	testCases := []struct {
		name     string
		object   client.Object
		expected bool
	}{
		{
			name: "matches",
			object: &gatewayv1beta1.GatewayClass{
				Spec: gatewayv1beta1.GatewayClassSpec{
					ControllerName: "foo",
				},
			},
			expected: true,
		},
		{
			name: "does not match",
			object: &gatewayv1beta1.GatewayClass{
				Spec: gatewayv1beta1.GatewayClassSpec{
					ControllerName: "bar",
				},
			},
			expected: false,
		},
		{
			name:     "not a GatewayClass",
			object:   &corev1.Service{},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, matchesControllerName("foo")(tc.object))
		})
	}
}
