// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

func TestValidateL7ProxyRedirection(t *testing.T) {
	tests := []struct {
		name           string
		enableL7Proxy  bool
		installIpt     bool
		enableBPFTProx bool
		wantErr        bool
	}{
		{
			name:           "L7 proxy disabled",
			enableL7Proxy:  false,
			installIpt:     false,
			enableBPFTProx: false,
			wantErr:        false,
		},
		{
			name:           "L7 proxy with iptables",
			enableL7Proxy:  true,
			installIpt:     true,
			enableBPFTProx: false,
			wantErr:        false,
		},
		{
			name:           "L7 proxy with BPF TProxy",
			enableL7Proxy:  true,
			installIpt:     false,
			enableBPFTProx: true,
			wantErr:        false,
		},
		{
			name:           "L7 proxy with both iptables and BPF TProxy",
			enableL7Proxy:  true,
			installIpt:     true,
			enableBPFTProx: true,
			wantErr:        false,
		},
		{
			name:           "L7 proxy without iptables or BPF TProxy",
			enableL7Proxy:  true,
			installIpt:     false,
			enableBPFTProx: false,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &option.DaemonConfig{
				EnableL7Proxy:  tt.enableL7Proxy,
				InstallIptRules: tt.installIpt,
				EnableBPFTProxy: tt.enableBPFTProx,
			}
			err := validateL7ProxyRedirection(cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
