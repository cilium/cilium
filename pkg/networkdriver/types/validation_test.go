// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateInterfaceSysctl(t *testing.T) {
	tests := []struct {
		name    string
		ipv4    map[string]string
		ipv6    map[string]string
		wantErr bool
	}{
		{
			name: "empty",
		},
		{
			name: "valid leaves both families",
			ipv4: map[string]string{"arp_filter": "1"},
			ipv6: map[string]string{"disable_ipv6": "0"},
		},
		{
			name:    "invalid ipv4 leaf character",
			ipv4:    map[string]string{"arp filter": "1"},
			wantErr: true,
		},
		{
			name:    "invalid ipv6 leaf character",
			ipv6:    map[string]string{"disable ipv6": "0"},
			wantErr: true,
		},
		{
			name:    "empty ipv4 value",
			ipv4:    map[string]string{"arp_filter": ""},
			wantErr: true,
		},
		{
			name:    "empty ipv6 value",
			ipv6:    map[string]string{"disable_ipv6": ""},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DeviceConfig{InterfaceSysctlIPv4: tc.ipv4, InterfaceSysctlIPv6: tc.ipv6}
			err := cfg.validateInterfaceSysctl()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
