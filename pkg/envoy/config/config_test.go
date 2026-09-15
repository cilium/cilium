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
		name    string
		mode    XDSMode
		wantErr bool
	}{
		{
			name: "split mode",
			mode: EnvoyXDSModeSplit,
		},
		{
			name: "delta split mode",
			mode: EnvoyXDSModeDeltaSplit,
		},
		{
			name: "ADS mode",
			mode: EnvoyXDSModeADS,
		},
		{
			name: "delta ADS mode",
			mode: EnvoyXDSModeDeltaADS,
		},
		{
			name: "strict ADS mode",
			mode: EnvoyXDSModeStrictADS,
		},
		{
			name: "strict delta ADS mode",
			mode: EnvoyXDSModeStrictDeltaADS,
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
		})
	}
}

func TestEnvoyXDSModeHelpers(t *testing.T) {
	tests := []struct {
		mode       XDSMode
		isADS      bool
		isDelta    bool
		isDeltaADS bool
		isStrict   bool
		apiType    envoy_config_core.ApiConfigSource_ApiType
	}{
		{mode: "", apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: EnvoyXDSModeSplit, apiType: envoy_config_core.ApiConfigSource_GRPC},
		{mode: EnvoyXDSModeDeltaSplit, isDelta: true, apiType: envoy_config_core.ApiConfigSource_DELTA_GRPC},
		{mode: EnvoyXDSModeADS, isADS: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_GRPC},
		{mode: EnvoyXDSModeDeltaADS, isADS: true, isDelta: true, isDeltaADS: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_DELTA_GRPC},
		{mode: EnvoyXDSModeStrictADS, isADS: true, isStrict: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_GRPC},
		{mode: EnvoyXDSModeStrictDeltaADS, isADS: true, isDelta: true, isDeltaADS: true, isStrict: true, apiType: envoy_config_core.ApiConfigSource_AGGREGATED_DELTA_GRPC},
	}

	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			require.Equal(t, tt.isADS, tt.mode.IsADS())
			require.Equal(t, tt.isDelta, tt.mode.IsDelta())
			require.Equal(t, tt.isDeltaADS, tt.mode.IsDeltaADS())
			require.Equal(t, tt.isStrict, tt.mode.IsStrictADS())
			require.Equal(t, tt.apiType, tt.mode.EnvoyApiType())
		})
	}
}
