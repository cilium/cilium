// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/redirectpolicy"
)

func TestLRPConfig(t *testing.T) {
	type args struct {
		lrpConfig redirectpolicy.LRPConfig
	}
	type metrics struct {
		npLRPConfigIngested float64
	}
	type wanted struct {
		wantMetrics metrics
	}
	tests := []struct {
		name string
		args args
		want wanted
	}{
		{
			name: "LRP Config",
			args: args{
				lrpConfig: redirectpolicy.LRPConfig{},
			},
			want: wanted{
				wantMetrics: metrics{
					npLRPConfigIngested: 1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddLRPConfig(&tt.args.lrpConfig)

			assert.Equalf(t, tt.want.wantMetrics.npLRPConfigIngested, metrics.NPLRPIngested.WithLabelValues(actionAdd).Get(), "NPLRPIngested different")
			assert.Equalf(t, float64(0), metrics.NPLRPIngested.WithLabelValues(actionDel).Get(), "NPLRPIngested different")

			metrics.DelLRPConfig(&tt.args.lrpConfig)

			assert.Equalf(t, tt.want.wantMetrics.npLRPConfigIngested, metrics.NPLRPIngested.WithLabelValues(actionAdd).Get(), "NPLRPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npLRPConfigIngested, metrics.NPLRPIngested.WithLabelValues(actionDel).Get(), "NPLRPIngested different")

		})
	}
}
