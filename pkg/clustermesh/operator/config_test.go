// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestClusterMeshConfig_Flags(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ClusterMeshConfig
		expected map[string]string
	}{
		{
			name: "Default configuration",
			cfg:  ClusterMeshConfig{},
			expected: map[string]string{
				"clustermesh-enable-endpoint-sync": "false",
			},
		},
		{
			name: "All flags enabled",
			cfg: ClusterMeshConfig{
				ClusterMeshEnableEndpointSync: true,
			},
			expected: map[string]string{
				"clustermesh-enable-endpoint-sync": "true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			tt.cfg.Flags(flags)

			// Check that all expected flags are registered
			for flagName, expectedValue := range tt.expected {
				flag := flags.Lookup(flagName)
				require.NotNil(t, flag, "Flag %s should be registered", flagName)
				require.Equal(t, expectedValue, flag.DefValue, "Flag %s default value mismatch", flagName)
			}
		})
	}
}

func TestMCSAPIConfig_Flags(t *testing.T) {
	t.Run("MCS API flag registration", func(t *testing.T) {
		cfg := MCSAPIConfig{}
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		cfg.Flags(flags)

		flag := flags.Lookup("clustermesh-enable-mcs-api")
		require.NotNil(t, flag)
		require.Equal(t, "bool", flag.Value.Type())
		require.Equal(t, "false", flag.DefValue)
	})
}

func TestMCSAPIConfigExtended(t *testing.T) {
	// Extended tests for MCS API configuration
	t.Run("MCS_API_flag_defaults", func(t *testing.T) {
		cfg := MCSAPIConfig{}
		
		// Verify default value before flag registration
		require.False(t, cfg.ClusterMeshEnableMCSAPI, "MCS API should be disabled by default")
		
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		cfg.Flags(flags)
		
		// Verify flag is registered with correct default
		flag := flags.Lookup("clustermesh-enable-mcs-api")
		require.NotNil(t, flag)
		require.Equal(t, "false", flag.DefValue, "MCS API flag should default to false")
	})
	
	t.Run("MCS_API_configuration_scenarios", func(t *testing.T) {
		scenarios := []struct {
			name           string
			flagValue      string
			expectedResult bool
		}{
			{"explicitly_enabled", "true", true},
			{"explicitly_disabled", "false", false},
			{"capitalized_true", "True", true},
			{"capitalized_false", "False", false},
		}
		
		for _, scenario := range scenarios {
			t.Run(scenario.name, func(t *testing.T) {
				cfg := MCSAPIConfig{}
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				cfg.Flags(flags)
				
				err := flags.Set("clustermesh-enable-mcs-api", scenario.flagValue)
				require.NoError(t, err)
				
				flag := flags.Lookup("clustermesh-enable-mcs-api")
				require.NotNil(t, flag)
				expectedStr := "false"
				if scenario.expectedResult {
					expectedStr = "true"
				}
				require.Equal(t, expectedStr, flag.Value.String())
			})
		}
	})
}