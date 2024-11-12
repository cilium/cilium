// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/operator/option"
)

type mockFeaturesParams struct {
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
