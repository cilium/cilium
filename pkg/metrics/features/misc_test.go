// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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

func TestCiliumEnvoyConfig(t *testing.T) {
	type args struct {
		cec ciliumv2.CiliumEnvoyConfigSpec
	}
	type metrics struct {
		aclbCiliumEnvoyConfigIngested float64
		aclbCiliumEnvoyConfigPresent  float64
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
			name: "CiliumEnvoyConfig",
			args: args{
				cec: ciliumv2.CiliumEnvoyConfigSpec{},
			},
			want: wanted{
				wantMetrics: metrics{
					aclbCiliumEnvoyConfigIngested: 1,
					aclbCiliumEnvoyConfigPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCEC(&tt.args.cec)

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumEnvoyConfigIngested, metrics.ACLBCiliumEnvoyConfigIngested.Get(), "aclbCiliumEnvoyConfigIngested different")
			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumEnvoyConfigPresent, metrics.ACLBCiliumEnvoyConfigPresent.Get(), "aclbCiliumEnvoyConfigPresent different")

			metrics.DelCEC(&tt.args.cec)

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumEnvoyConfigIngested, metrics.ACLBCiliumEnvoyConfigIngested.Get(), "aclbCiliumEnvoyConfigIngested different")
			assert.Equalf(t, float64(0), metrics.ACLBCiliumEnvoyConfigPresent.Get(), "aclbCiliumEnvoyConfigPresent different")

		})
	}
}

func TestCiliumClusterwideEnvoyConfig(t *testing.T) {
	type args struct {
		cec ciliumv2.CiliumEnvoyConfigSpec
	}
	type metrics struct {
		aclbCiliumClusterwideEnvoyConfigIngested float64
		aclbCiliumClusterwideEnvoyConfigPresent  float64
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
			name: "CiliumClusterwideEnvoyConfig",
			args: args{
				cec: ciliumv2.CiliumEnvoyConfigSpec{},
			},
			want: wanted{
				wantMetrics: metrics{
					aclbCiliumClusterwideEnvoyConfigIngested: 1,
					aclbCiliumClusterwideEnvoyConfigPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCCEC(&tt.args.cec)

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumClusterwideEnvoyConfigIngested, metrics.ACLBCiliumClusterwideEnvoyConfigIngested.Get(), "aclbCiliumClusterwideEnvoyConfigIngested different")
			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumClusterwideEnvoyConfigPresent, metrics.ACLBCiliumClusterwideEnvoyConfigPresent.Get(), "aclbCiliumClusterwideEnvoyConfigPresent different")

			metrics.DelCCEC(&tt.args.cec)

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumClusterwideEnvoyConfigIngested, metrics.ACLBCiliumClusterwideEnvoyConfigIngested.Get(), "aclbCiliumClusterwideEnvoyConfigIngested different")
			assert.Equalf(t, float64(0), metrics.ACLBCiliumClusterwideEnvoyConfigPresent.Get(), "aclbCiliumClusterwideEnvoyConfigPresent different")

		})
	}
}

func TestCNP(t *testing.T) {
	type args struct {
		cnp ciliumv2.CiliumNetworkPolicy
	}
	type metrics struct {
		npCNPIngested float64
		npCNPPresent  float64
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
			name: "CNP",
			args: args{
				cnp: ciliumv2.CiliumNetworkPolicy{},
			},
			want: wanted{
				wantMetrics: metrics{
					npCNPIngested: 1,
					npCNPPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCNPIngested, metrics.NPCNPIngested.Get(), "npCNPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npCNPPresent, metrics.NPCNPPresent.Get(), "npCNPPresent different")

			metrics.DelCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCNPIngested, metrics.NPCNPIngested.Get(), "npCNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPCNPPresent.Get(), "npCNPPresent different")

		})
	}
}

func TestCCNP(t *testing.T) {
	type args struct {
		cnp ciliumv2.CiliumNetworkPolicy
	}
	type metrics struct {
		npCCNPIngested float64
		npCCNPPresent  float64
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
			name: "CCNP",
			args: args{
				cnp: ciliumv2.CiliumNetworkPolicy{},
			},
			want: wanted{
				wantMetrics: metrics{
					npCCNPIngested: 1,
					npCCNPPresent:  1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCCNPIngested, metrics.NPCCNPIngested.Get(), "NPCCNPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npCCNPPresent, metrics.NPCCNPPresent.Get(), "NPCCNPPresent different")

			metrics.DelCCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCCNPIngested, metrics.NPCCNPIngested.Get(), "NPCCNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPCCNPPresent.Get(), "NPCCNPPresent different")

		})
	}
}
