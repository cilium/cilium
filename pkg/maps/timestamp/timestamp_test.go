// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package timestamp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
)

func TestConvert(t *testing.T) {
	tests := []struct {
		name  string
		mode  string
		hertz int64
		err   bool
		inp   uint64
		res   uint64
	}{
		{name: "ktime", mode: models.ClockSourceModeKtime, inp: uint64(0xff00ff0012345678), res: uint64(0xff00ff0012345678)},
		{name: "jiffies_err", mode: models.ClockSourceModeJiffies, err: true},
		{name: "jiffies_ok", mode: models.ClockSourceModeJiffies, hertz: 100, inp: uint64(0x00ffff0012345678), res: uint64(0x28f5999c834108f)},
		{name: "invalid", mode: "", err: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clockSource := &models.ClockSource{Mode: tt.mode, Hertz: tt.hertz}
			conv, err := NewCTTimeToSecConverter(clockSource)
			if tt.err {
				require.Error(t, err, "Invalid converter created")
			} else {
				require.NoError(t, err, "Failed to create converter")
				res := conv(tt.inp)
				require.Equal(t, tt.res, res)
			}
		})
	}
}
