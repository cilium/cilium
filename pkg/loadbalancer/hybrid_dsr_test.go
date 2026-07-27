// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/u8proto"
)

func TestToSVCForwardingMode_Hybrid(t *testing.T) {
	tests := []struct {
		name     string
		lbMode   string
		proto    []uint8
		expected SVCForwardingMode
	}{
		{
			name:     "Hybrid mode with TCP should return DSR",
			lbMode:   LBModeHybrid,
			proto:    []uint8{uint8(u8proto.TCP)},
			expected: SVCForwardingModeDSR,
		},
		{
			name:     "Hybrid mode with UDP should return SNAT",
			lbMode:   LBModeHybrid,
			proto:    []uint8{uint8(u8proto.UDP)},
			expected: SVCForwardingModeSNAT,
		},
		{
			name:     "Hybrid mode with SCTP should return SNAT",
			lbMode:   LBModeHybrid,
			proto:    []uint8{uint8(u8proto.SCTP)},
			expected: SVCForwardingModeSNAT,
		},
		{
			name:     "Hybrid mode without protocol should return SNAT",
			lbMode:   LBModeHybrid,
			proto:    nil,
			expected: SVCForwardingModeSNAT,
		},
		{
			name:     "DSR mode with TCP should return DSR",
			lbMode:   LBModeDSR,
			proto:    []uint8{uint8(u8proto.TCP)},
			expected: SVCForwardingModeDSR,
		},
		{
			name:     "DSR mode with UDP should return DSR",
			lbMode:   LBModeDSR,
			proto:    []uint8{uint8(u8proto.UDP)},
			expected: SVCForwardingModeDSR,
		},
		{
			name:     "DSR mode without protocol should return DSR",
			lbMode:   LBModeDSR,
			proto:    nil,
			expected: SVCForwardingModeDSR,
		},
		{
			name:     "SNAT mode with TCP should return SNAT",
			lbMode:   LBModeSNAT,
			proto:    []uint8{uint8(u8proto.TCP)},
			expected: SVCForwardingModeSNAT,
		},
		{
			name:     "SNAT mode with UDP should return SNAT",
			lbMode:   LBModeSNAT,
			proto:    []uint8{uint8(u8proto.UDP)},
			expected: SVCForwardingModeSNAT,
		},
		{
			name:     "SNAT mode without protocol should return SNAT",
			lbMode:   LBModeSNAT,
			proto:    nil,
			expected: SVCForwardingModeSNAT,
		},
		{
			name:     "Unknown mode should return Undef",
			lbMode:   "unknown",
			proto:    []uint8{uint8(u8proto.TCP)},
			expected: SVCForwardingModeUndef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToSVCForwardingMode(tt.lbMode, tt.proto...)
			require.Equal(t, tt.expected, result)
		})
	}
}
