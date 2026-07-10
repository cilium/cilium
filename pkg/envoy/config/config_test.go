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
		mode    string
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
			err := (ProxyConfig{EnvoyXDSMode: tt.mode}).Validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestEnvoyXDSModeHelpers(t *testing.T) {
	require.False(t, ADSModeEnabled(""))
	require.False(t, StrictADSModeEnabled(""))
	require.False(t, ADSModeEnabled(EnvoyXDSModeSplit))
	require.False(t, StrictADSModeEnabled(EnvoyXDSModeSplit))

	require.True(t, ADSModeEnabled(EnvoyXDSModeADS))
	require.False(t, StrictADSModeEnabled(EnvoyXDSModeADS))

	require.True(t, ADSModeEnabled(EnvoyXDSModeStrictADS))
	require.True(t, StrictADSModeEnabled(EnvoyXDSModeStrictADS))
}
