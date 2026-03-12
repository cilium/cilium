// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestIsOperatorManaged(t *testing.T) {
	tests := []struct {
		name     string
		config   *v2alpha1.CiliumNetworkDriverNodeConfig
		expected bool
	}{
		{
			name: "operator managed",
			config: &v2alpha1.CiliumNetworkDriverNodeConfig{
				Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
					ManagedBy: ManagedByOperator,
				},
			},
			expected: true,
		},
		{
			name: "user managed",
			config: &v2alpha1.CiliumNetworkDriverNodeConfig{
				Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
					ManagedBy: "user",
				},
			},
			expected: false,
		},
		{
			name: "empty managed by",
			config: &v2alpha1.CiliumNetworkDriverNodeConfig{
				Status: v2alpha1.CiliumNetworkDriverNodeConfigStatus{
					ManagedBy: "",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isOperatorManaged(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegisterConfigReconciler_DisabledClientset(t *testing.T) {
	// Test that registration with disabled clientset doesn't panic
	params := ConfigReconcilerParams{}
	registerConfigReconciler(params)
}
