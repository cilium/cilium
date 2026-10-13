// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

func TestLoadVTEPMask(t *testing.T) {
	originalConfig := option.Config
	t.Cleanup(func() {
		option.Config = originalConfig
	})

	runtimeConfig := *originalConfig
	runtimeConfig.VtepCidrMask = netip.MustParseAddr("255.255.0.0")
	runtimeConfigJSON, err := json.Marshal(&runtimeConfig)
	require.NoError(t, err)

	for _, tt := range []struct {
		name    string
		data    string
		mask    string
		wantErr string
	}{
		{
			name: "IPv4 mask",
			data: `{"VtepCidrMask":"255.255.255.0","EnableIPv4":false}`,
			mask: "255.255.255.0",
		},
		{
			name: "non-default IPv4 mask",
			data: `{"VtepCidrMask":"255.255.0.0"}`,
			mask: "255.255.0.0",
		},
		{
			name: "serialized agent runtime configuration",
			data: string(runtimeConfigJSON),
			mask: "255.255.0.0",
		},
		{
			name:    "missing mask",
			data:    `{}`,
			wantErr: "must be an IPv4 address",
		},
		{
			name:    "empty mask",
			data:    `{"VtepCidrMask":""}`,
			wantErr: "must be an IPv4 address",
		},
		{
			name:    "IPv6 mask",
			data:    `{"VtepCidrMask":"fd00::1"}`,
			wantErr: "must be an IPv4 address",
		},
		{
			name:    "IPv4-mapped IPv6 mask",
			data:    `{"VtepCidrMask":"::ffff:255.255.255.0"}`,
			wantErr: "must be an IPv4 address",
		},
		{
			name:    "invalid mask",
			data:    `{"VtepCidrMask":"invalid"}`,
			wantErr: "failed to parse agent runtime configuration",
		},
		{
			name:    "malformed configuration",
			data:    `{`,
			wantErr: "failed to parse agent runtime configuration",
		},
		{
			name:    "missing configuration file",
			wantErr: "failed to read agent runtime configuration",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := &option.DaemonConfig{EnableIPv4: true}
			option.Config = config
			configFile := filepath.Join(t.TempDir(), "agent-runtime-config.json")
			if tt.data != "" {
				require.NoError(t, os.WriteFile(configFile, []byte(tt.data), 0600))
			}

			err := loadVTEPMask(configFile)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.False(t, config.VtepCidrMask.IsValid())
			} else {
				require.NoError(t, err)
				require.Equal(t, netip.MustParseAddr(tt.mask), config.VtepCidrMask)
				require.NotPanics(t, func() {
					config.VtepCidrMask.As4()
				})
			}
			require.Same(t, config, option.Config)
			require.True(t, config.EnableIPv4)
		})
	}
}
