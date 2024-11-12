// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/option"
)

type mockFeaturesParams struct {
	IngressControllerEnabled bool
}

func (p mockFeaturesParams) IsIngressControllerEnabled() bool {
	return p.IngressControllerEnabled
}

func TestUpdateGatewayAPI(t *testing.T) {
	tests := []struct {
		name             string
		enableGatewayAPI bool
		expected         float64
	}{
		{
			name:             "Gateway API enabled",
			enableGatewayAPI: true,
			expected:         1,
		},
		{
			name:             "Gateway API disabled",
			enableGatewayAPI: false,
			expected:         0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.OperatorConfig{
				EnableGatewayAPI: tt.enableGatewayAPI,
			}

			params := mockFeaturesParams{}

			metrics.update(params, config)

			counterValue := metrics.ACLBGatewayAPIEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableGatewayAPI, counterValue)
		})
	}
}

func TestUpdateIngressControllerEnabled(t *testing.T) {
	tests := []struct {
		name                           string
		enableIngressControllerEnabled bool
		expected                       float64
	}{
		{
			name:                           "IngressController enabled",
			enableIngressControllerEnabled: true,
			expected:                       1,
		},
		{
			name:                           "IngressController disabled",
			enableIngressControllerEnabled: false,
			expected:                       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.OperatorConfig{}

			params := mockFeaturesParams{
				IngressControllerEnabled: tt.enableIngressControllerEnabled,
			}

			metrics.update(params, config)

			counterValue := metrics.ACLBIngressControllerEnabled.Get()
			assert.Equal(t, tt.expected, counterValue, "Expected value to be %.f for enabled: %t, got %.f", tt.expected, tt.enableIngressControllerEnabled, counterValue)
		})
	}
}
