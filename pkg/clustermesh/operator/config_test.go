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
				"clustermesh-enable-endpoint-sync":      "false",
				"clustermesh-default-global-namespace": "false",
			},
		},
		{
			name: "All flags enabled",
			cfg: ClusterMeshConfig{
				ClusterMeshEnableEndpointSync:     true,
				ClusterMeshDefaultGlobalNamespace: true,
			},
			expected: map[string]string{
				"clustermesh-enable-endpoint-sync":      "true",
				"clustermesh-default-global-namespace": "true",
			},
		},
		{
			name: "Mixed configuration",
			cfg: ClusterMeshConfig{
				ClusterMeshEnableEndpointSync:     true,
				ClusterMeshDefaultGlobalNamespace: false,
			},
			expected: map[string]string{
				"clustermesh-enable-endpoint-sync":      "true",
				"clustermesh-default-global-namespace": "false",
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

func TestClusterMeshDefaultGlobalNamespaceFlag(t *testing.T) {
	t.Run("Flag registration and default value", func(t *testing.T) {
		cfg := ClusterMeshConfig{}
		flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
		cfg.Flags(flags)

		flag := flags.Lookup("clustermesh-default-global-namespace")
		require.NotNil(t, flag)
		require.Equal(t, "bool", flag.Value.Type())
		require.Equal(t, "false", flag.DefValue)
		require.Contains(t, flag.Usage, "Determines default behavior for namespaces when filtering is active")
		require.Contains(t, flag.Usage, "When true, namespaces are global by default")
		require.Contains(t, flag.Usage, "When false, namespaces are local by default")
	})

	t.Run("Flag parsing", func(t *testing.T) {
		tests := []struct {
			name     string
			args     []string
			expected bool
		}{
			{
				name:     "Default value",
				args:     []string{},
				expected: false,
			},
			{
				name:     "Explicitly set to true",
				args:     []string{"--clustermesh-default-global-namespace=true"},
				expected: true,
			},
			{
				name:     "Explicitly set to false",
				args:     []string{"--clustermesh-default-global-namespace=false"},
				expected: false,
			},
			{
				name:     "Short flag syntax",
				args:     []string{"--clustermesh-default-global-namespace"},
				expected: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := ClusterMeshConfig{}
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				cfg.Flags(flags)

				err := flags.Parse(tt.args)
				require.NoError(t, err)

				val, err := flags.GetBool("clustermesh-default-global-namespace")
				require.NoError(t, err)
				require.Equal(t, tt.expected, val)
			})
		}
	})
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
		require.Contains(t, flag.Usage, "Whether or not the MCS API support is enabled")
	})
}