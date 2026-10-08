// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/option"
)

func TestNewConfig_NodePortRange(t *testing.T) {
	type want struct {
		wantMin uint16
		wantMax uint16
		wantErr bool
	}
	tests := []struct {
		name    string
		want    want
		npRange []string
	}{
		{
			name: "NodePortRange is valid",
			want: want{
				wantMin: 23,
				wantMax: 24,
				wantErr: false,
			},
			npRange: []string{"23", "24"},
		},
		{
			name: "NodePortMin greater than NodePortMax",
			want: want{
				wantMin: 666,
				wantMax: 555,
				wantErr: true,
			},
			npRange: []string{"666", "555"},
		},
		{
			name: "NodePortMin equal NodePortMax",
			want: want{
				wantMin: 666,
				wantMax: 666,
				wantErr: true,
			},
			npRange: []string{"666", "666"},
		},
		{
			name: "NodePortMin not a number",
			want: want{
				wantMin: 0,
				wantMax: 0,
				wantErr: true,
			},
			npRange: []string{"aaa", "0"},
		},
		{
			name: "NodePortMax not a number",
			want: want{
				wantMin: 1024,
				wantMax: 0,
				wantErr: true,
			},
			npRange: []string{"1024", "aaa"},
		},
		{
			name: "NodePortRange slice length not equal 2",
			want: want{
				wantMin: 0,
				wantMax: 0,
				wantErr: true,
			},
			npRange: []string{"1024"},
		},
		{
			name: "NodePortRange passed as empty uses defaults",
			want: want{
				wantMin: NodePortMinDefault,
				wantMax: NodePortMaxDefault,
				wantErr: false,
			},
			npRange: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t)
			ucfg := DefaultUserConfig
			ucfg.NodePortRange = tt.npRange
			cfg, err := NewConfig(log, ucfg, &option.DaemonConfig{})

			if tt.want.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.wantMin, cfg.NodePortMin, "min mismatch")
				assert.Equal(t, tt.want.wantMax, cfg.NodePortMax, "max mismatch")
			}
		})
	}
}

func TestNewConfig_NodePortNATRangeExt(t *testing.T) {
	type want struct {
		wantMin uint16
		wantMax uint16
		wantErr bool
	}
	tests := []struct {
		name     string
		want     want
		extRange []string
	}{
		{
			name: "NodePortNATRangeExt valid slice",
			want: want{
				wantMin: 1024,
				wantMax: 29999,
				wantErr: false,
			},
			extRange: []string{"1024", "29999"},
		},
		{
			name: "NodePortNATRangeExt valid comma-separated string",
			want: want{
				wantMin: 1024,
				wantMax: 29999,
				wantErr: false,
			},
			extRange: []string{"1024,29999"},
		},
		{
			name: "NodePortNATRangeExt min in privileged port range (< 1024)",
			want: want{
				wantErr: true,
			},
			extRange: []string{"512", "29999"},
		},
		{
			name: "NodePortNATRangeExt min >= max",
			want: want{
				wantErr: true,
			},
			extRange: []string{"20000", "10000"},
		},
		{
			name: "NodePortNATRangeExt overlaps with NodePort range",
			want: want{
				wantErr: true,
			},
			extRange: []string{"1024", "30000"},
		},
		{
			name: "NodePortNATRangeExt empty uses defaults (0, 0)",
			want: want{
				wantMin: 0,
				wantMax: 0,
				wantErr: false,
			},
			extRange: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := hivetest.Logger(t)
			ucfg := DefaultUserConfig
			ucfg.NodePortNATRangeExt = tt.extRange
			cfg, err := NewConfig(log, ucfg, &option.DaemonConfig{})

			if tt.want.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.wantMin, cfg.NodePortMinNATExt, "ext min mismatch")
				assert.Equal(t, tt.want.wantMax, cfg.NodePortMaxNATExt, "ext max mismatch")
			}
		})
	}
}
