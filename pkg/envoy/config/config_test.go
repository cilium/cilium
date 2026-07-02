// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

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
			name: "ADS mode",
			mode: EnvoyXDSModeADS,
		},
		{
			name: "strict ADS mode",
			mode: EnvoyXDSModeStrictADS,
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
	require.False(t, XDSMode("").IsADS())
	require.False(t, XDSMode("").IsStrictADS())
	require.False(t, EnvoyXDSModeSplit.IsADS())
	require.False(t, EnvoyXDSModeSplit.IsStrictADS())

	require.True(t, EnvoyXDSModeADS.IsADS())
	require.False(t, EnvoyXDSModeADS.IsStrictADS())

	require.True(t, EnvoyXDSModeStrictADS.IsADS())
	require.True(t, EnvoyXDSModeStrictADS.IsStrictADS())
}
