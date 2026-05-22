// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
			object: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{
					ControllerName: "foo",
				},
			},
			expected: true,
		},
		{
			name: "does not match",
			object: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{
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

func Test_referencedConfig(t *testing.T) {
	testCases := []struct {
		name     string
		object   client.Object
		expected []string
	}{
		{
			name: "cilium GatewayClass with supported parametersRef",
			object: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{
					ControllerName: helpers.CiliumDefaultControllerName,
					ParametersRef: &gatewayv1.ParametersReference{
						Group:     v2alpha1.CustomResourceDefinitionGroup,
						Kind:      v2alpha1.CGCCKindDefinition,
						Name:      "dummy-gateway-class-config",
						Namespace: ptr.To(gatewayv1.Namespace("default")),
					},
				},
			},
			expected: []string{types.NamespacedName{
				Namespace: "default",
				Name:      "dummy-gateway-class-config",
			}.String()},
		},
		{
			name: "non-Cilium GatewayClass with supported parametersRef",
			object: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{
					ControllerName: "not-cilium-controller-name",
					ParametersRef: &gatewayv1.ParametersReference{
						Group:     v2alpha1.CustomResourceDefinitionGroup,
						Kind:      v2alpha1.CGCCKindDefinition,
						Name:      "dummy-gateway-class-config",
						Namespace: ptr.To(gatewayv1.Namespace("default")),
					},
				},
			},
			expected: nil,
		},
		{
			name: "cilium GatewayClass with unsupported parametersRef",
			object: &gatewayv1.GatewayClass{
				Spec: gatewayv1.GatewayClassSpec{
					ControllerName: helpers.CiliumDefaultControllerName,
					ParametersRef: &gatewayv1.ParametersReference{
						Group:     "v1",
						Kind:      "ConfigMap",
						Name:      "dummy-cm",
						Namespace: ptr.To(gatewayv1.Namespace("default")),
					},
				},
			},
			expected: nil,
		},
		{
			name:     "not a GatewayClass",
			object:   &corev1.Service{},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, referencedConfig(tc.object))
		})
	}
}
