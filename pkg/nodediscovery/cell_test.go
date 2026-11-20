// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mode    string
		udp     bool
		wantErr bool
	}{
		{name: "defaults", mode: defaultConfig.ENIENAExpress, udp: defaultConfig.ENIENAExpressUDP},
		{name: "disabled", mode: "disabled"},
		{name: "enabled", mode: "enabled"},
		{name: "enabled with UDP", mode: "enabled", udp: true},
		{name: "inherit", mode: "inherit"},
		{name: "unknown mode", mode: "true", wantErr: true},
		{name: "mode is case sensitive", mode: "Enabled", wantErr: true},
		{name: "empty mode", mode: "", wantErr: true},
		{name: "UDP with disabled", mode: "disabled", udp: true, wantErr: true},
		{name: "UDP with inherit", mode: "inherit", udp: true, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig
			cfg.ENIENAExpress = tt.mode
			cfg.ENIENAExpressUDP = tt.udp

			err := cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
