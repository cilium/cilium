// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"
)

func TestValidateEnvoyXDSMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     XDSMode
		wantMode XDSMode
		wantErr  bool
	}{
		{
			name:     "split mode",
			mode:     EnvoyXDSModeSplit,
			wantMode: EnvoyXDSModeSplit,
		},
		{
			name:     "delta split mode",
			mode:     EnvoyXDSModeDeltaSplit,
			wantMode: EnvoyXDSModeDeltaSplit,
		},
		{
			name:     "ADS mode",
			mode:     EnvoyXDSModeADS,
			wantMode: EnvoyXDSModeADS,
		},
		{
			name:     "delta ADS mode",
			mode:     EnvoyXDSModeDeltaADS,
			wantMode: EnvoyXDSModeDeltaADS,
		},
		{
			name:     "strict ADS alias",
			mode:     EnvoyXDSModeStrictADS,
			wantMode: EnvoyXDSModeADS,
		},
		{
			name:    "strict delta ADS mode",
			mode:    EnvoyXDSModeStrictDeltaADS,
			wantErr: true,
		},
		{
			name:    "unknown mode",
			mode:    "sotw",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ProxyConfig{EnvoyXDSMode: tt.mode}
			err := config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantMode, config.EnvoyXDSMode)

			var mode XDSMode
			require.NoError(t, mode.Set(tt.mode.String()))
			require.Equal(t, tt.wantMode, mode)
		})
	}
}

func TestEnvoyXDSModeHelpers(t *testing.T) {
	tests := []struct {
		mode       XDSMode
		isADS      bool
		isDelta    bool
		isDeltaADS bool
		apiType    envoy_config_core.ApiConfigSource_ApiType
	}{
		{mode: "", apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: EnvoyXDSModeSplit, apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: EnvoyXDSModeDeltaSplit, isDelta: true, apiType: envoy_config_core.ApiConfigSource_DELTA_GRPC},
		{mode: EnvoyXDSModeADS, isADS: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_GRPC},
		{mode: EnvoyXDSModeDeltaADS, isADS: true, isDelta: true, isDeltaADS: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_DELTA_GRPC},
		{mode: EnvoyXDSModeStrictADS, isADS: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_GRPC},
		{mode: EnvoyXDSModeStrictDeltaADS, isADS: true, isDelta: true, isDeltaADS: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_DELTA_GRPC},
	}

	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			require.Equal(t, tt.isADS, tt.mode.IsADS())
			require.Equal(t, tt.isDelta, tt.mode.IsDelta())
			require.Equal(t, tt.isDeltaADS, tt.mode.IsDeltaADS())
			require.Equal(t, tt.apiType, tt.mode.EnvoyApiType())
		})
	}
}
