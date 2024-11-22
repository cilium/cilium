// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/redirectpolicy"
)

func TestLRPConfig(t *testing.T) {
	type args struct {
		lrpConfig redirectpolicy.LRPConfig
	}
	type metrics struct {
		npLRPConfigIngested float64
		npLRPConfigPresent  float64
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
					npLRPConfigPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddLRPConfig(&tt.args.lrpConfig)

			assert.Equalf(t, tt.want.wantMetrics.npLRPConfigIngested, metrics.NPLRPIngested.Get(), "NPLRPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npLRPConfigPresent, metrics.NPLRPPresent.Get(), "NPLRPPresent different")

			metrics.DelLRPConfig(&tt.args.lrpConfig)

			assert.Equalf(t, tt.want.wantMetrics.npLRPConfigIngested, metrics.NPLRPIngested.Get(), "NPLRPIngested different")
			assert.Equalf(t, float64(0), metrics.NPLRPPresent.Get(), "NPLRPPresent different")

		})
	}
}

func TestInternalTrafficPolicy(t *testing.T) {
	type args struct {
		svc k8s.Service
	}
	type metrics struct {
		aclbInternalTrafficPolicyIngested float64
		aclbInternalTrafficPolicyPresent  float64
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
			name: "InternalTrafficPolicy",
			args: args{
				svc: k8s.Service{
					IntTrafficPolicy: loadbalancer.SVCTrafficPolicyLocal,
				},
			},
			want: wanted{
				wantMetrics: metrics{
					aclbInternalTrafficPolicyIngested: 1,
					aclbInternalTrafficPolicyPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddService(&tt.args.svc)

			assert.Equalf(t, tt.want.wantMetrics.aclbInternalTrafficPolicyIngested, metrics.ACLBInternalTrafficPolicyIngested.Get(), "aclbInternalTrafficPolicyIngested different")
			assert.Equalf(t, tt.want.wantMetrics.aclbInternalTrafficPolicyPresent, metrics.ACLBInternalTrafficPolicyPresent.Get(), "aclbInternalTrafficPolicyPresent different")

			metrics.DelService(&tt.args.svc)

			assert.Equalf(t, tt.want.wantMetrics.aclbInternalTrafficPolicyIngested, metrics.ACLBInternalTrafficPolicyIngested.Get(), "aclbInternalTrafficPolicyIngested different")
			assert.Equalf(t, float64(0), metrics.ACLBInternalTrafficPolicyPresent.Get(), "aclbInternalTrafficPolicyPresent different")

		})
	}
}
