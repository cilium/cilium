// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetVLANFilter(t *testing.T) {
	const u = vlanFilterUnused

	tests := []struct {
		name string
		ids  []int
		want [VLANFilterSlots]uint16
	}{
		{
			name: "empty list fills all slots with the unused sentinel",
			ids:  nil,
			want: [VLANFilterSlots]uint16{u, u, u, u, u},
		},
		{
			name: "partial list pads remaining slots with the sentinel",
			ids:  []int{100, 200},
			want: [VLANFilterSlots]uint16{100, 200, u, u, u},
		},
		{
			name: "full list fills every slot",
			ids:  []int{1, 2, 3, 4, 5},
			want: [VLANFilterSlots]uint16{1, 2, 3, 4, 5},
		},
		{
			name: "zero means allow all and is stored verbatim",
			ids:  []int{0},
			want: [VLANFilterSlots]uint16{0, u, u, u, u},
		},
		{
			name: "entries beyond the slot count are ignored",
			ids:  []int{10, 20, 30, 40, 50, 60, 70},
			want: [VLANFilterSlots]uint16{10, 20, 30, 40, 50},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &BPFHost{}
			setVLANFilter(cfg, tt.ids)

			got := [VLANFilterSlots]uint16{
				cfg.VlanFilterID0, cfg.VlanFilterID1, cfg.VlanFilterID2,
				cfg.VlanFilterID3, cfg.VlanFilterID4,
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
