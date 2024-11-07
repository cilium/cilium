// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/option"

	"github.com/stretchr/testify/assert"
)

type mockFeaturesParams struct {
	TunnelConfig tunnel.Protocol
}

func (m mockFeaturesParams) TunnelProtocol() tunnel.Protocol {
	return m.TunnelConfig
}

func TestUpdateNetworkMode(t *testing.T) {
	tests := []struct {
		name         string
		tunnelMode   string
		tunnelProto  tunnel.Protocol
		expectedMode string
	}{
		{
			name:         "Direct routing mode",
			tunnelMode:   option.RoutingModeNative,
			expectedMode: networkModeDirectRouting,
		},
		{
			name:         "Overlay VXLAN mode",
			tunnelMode:   option.RoutingModeTunnel,
			tunnelProto:  tunnel.VXLAN,
			expectedMode: networkModeOverlayVXLAN,
		},
		{
			name:         "Overlay Geneve mode",
			tunnelMode:   option.RoutingModeTunnel,
			tunnelProto:  tunnel.Geneve,
			expectedMode: networkModeOverlayGENEVE,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := NewMetrics(true)
			config := &option.DaemonConfig{}
			config.RoutingMode = tt.tunnelMode

			params := mockFeaturesParams{
				TunnelConfig: tt.tunnelProto,
			}

			metrics.update(params, config)

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultNetworkModes {
				counter, err := metrics.DPMode.GetMetricWithLabelValues(mode)
				assert.NoError(t, err)

				counterValue := counter.Get()
				if mode == tt.expectedMode {
					assert.Equal(t, float64(1), counterValue, "Expected mode %s to be incremented", mode)
				} else {
					assert.Equal(t, float64(0), counterValue, "Expected mode %s to remain at 0", mode)
				}
			}
		})
	}
}
