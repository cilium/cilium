// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

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
			name:     "ADS mode",
			mode:     EnvoyXDSModeADS,
			wantMode: EnvoyXDSModeADS,
		},
		{
			name:     "strict ADS alias",
			mode:     EnvoyXDSModeStrictADS,
			wantMode: EnvoyXDSModeADS,
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
	require.False(t, XDSMode("").IsADS())
	require.False(t, EnvoyXDSModeSplit.IsADS())

	require.True(t, EnvoyXDSModeADS.IsADS())

	require.True(t, EnvoyXDSModeStrictADS.IsADS())
}
