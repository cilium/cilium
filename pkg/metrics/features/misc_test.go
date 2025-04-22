// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package features

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/redirectpolicy"
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

func TestInternalTrafficPolicy(t *testing.T) {
	type args struct {
		svc k8s.Service
	}
	type metrics struct {
		aclbInternalTrafficPolicyIngested float64
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddService(&tt.args.svc)

			assert.Equalf(t, tt.want.wantMetrics.aclbInternalTrafficPolicyIngested, metrics.ACLBInternalTrafficPolicyIngested.WithLabelValues(actionAdd).Get(), "ACLBInternalTrafficPolicyIngested different")
			assert.Equalf(t, float64(0), metrics.ACLBInternalTrafficPolicyIngested.WithLabelValues(actionDel).Get(), "ACLBInternalTrafficPolicyIngested different")

			metrics.DelService(&tt.args.svc)

			assert.Equalf(t, tt.want.wantMetrics.aclbInternalTrafficPolicyIngested, metrics.ACLBInternalTrafficPolicyIngested.WithLabelValues(actionAdd).Get(), "ACLBInternalTrafficPolicyIngested different")
			assert.Equalf(t, tt.want.wantMetrics.aclbInternalTrafficPolicyIngested, metrics.ACLBInternalTrafficPolicyIngested.WithLabelValues(actionDel).Get(), "ACLBInternalTrafficPolicyIngested different")

		})
	}
}

func TestCiliumEnvoyConfig(t *testing.T) {
	type args struct {
		cec ciliumv2.CiliumEnvoyConfigSpec
	}
	type metrics struct {
		aclbCiliumEnvoyConfigIngested float64
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCEC()

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumEnvoyConfigIngested, metrics.ACLBCiliumEnvoyConfigIngested.WithLabelValues(actionAdd).Get(), "ACLBCiliumEnvoyConfigIngested different")
			assert.Equalf(t, float64(0), metrics.ACLBCiliumEnvoyConfigIngested.WithLabelValues(actionDel).Get(), "ACLBCiliumEnvoyConfigIngested different")

			metrics.DelCEC()

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumEnvoyConfigIngested, metrics.ACLBCiliumEnvoyConfigIngested.WithLabelValues(actionAdd).Get(), "ACLBCiliumEnvoyConfigIngested different")
			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumEnvoyConfigIngested, metrics.ACLBCiliumEnvoyConfigIngested.WithLabelValues(actionDel).Get(), "ACLBCiliumEnvoyConfigIngested different")

		})
	}
}

func TestCiliumClusterwideEnvoyConfig(t *testing.T) {
	type args struct {
		cec ciliumv2.CiliumEnvoyConfigSpec
	}
	type metrics struct {
		aclbCiliumClusterwideEnvoyConfigIngested float64
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCCEC()

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumClusterwideEnvoyConfigIngested, metrics.ACLBCiliumClusterwideEnvoyConfigIngested.WithLabelValues(actionAdd).Get(), "ACLBCiliumClusterwideEnvoyConfigIngested different")
			assert.Equalf(t, float64(0), metrics.ACLBCiliumClusterwideEnvoyConfigIngested.WithLabelValues(actionDel).Get(), "ACLBCiliumClusterwideEnvoyConfigIngested different")

			metrics.DelCCEC()

			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumClusterwideEnvoyConfigIngested, metrics.ACLBCiliumClusterwideEnvoyConfigIngested.WithLabelValues(actionAdd).Get(), "ACLBCiliumClusterwideEnvoyConfigIngested different")
			assert.Equalf(t, tt.want.wantMetrics.aclbCiliumClusterwideEnvoyConfigIngested, metrics.ACLBCiliumClusterwideEnvoyConfigIngested.WithLabelValues(actionDel).Get(), "ACLBCiliumClusterwideEnvoyConfigIngested different")

		})
	}
}

func TestCNP(t *testing.T) {
	type args struct {
		cnp ciliumv2.CiliumNetworkPolicy
	}
	type metrics struct {
		npCNPIngested float64
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCNPIngested, metrics.NPCNPIngested.WithLabelValues(actionAdd).Get(), "NPCNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPCNPIngested.WithLabelValues(actionDel).Get(), "NPCNPIngested different")

			metrics.DelCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCNPIngested, metrics.NPCNPIngested.WithLabelValues(actionAdd).Get(), "NPCNPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npCNPIngested, metrics.NPCNPIngested.WithLabelValues(actionDel).Get(), "NPCNPIngested different")

		})
	}
}

func TestCCNP(t *testing.T) {
	type args struct {
		cnp ciliumv2.CiliumNetworkPolicy
	}
	type metrics struct {
		npCCNPIngested float64
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
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			metrics := NewMetrics(true)
			metrics.AddCCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCCNPIngested, metrics.NPCCNPIngested.WithLabelValues(actionAdd).Get(), "NPCCNPIngested different")
			assert.Equalf(t, float64(0), metrics.NPCCNPIngested.WithLabelValues(actionDel).Get(), "NPCCNPIngested different")

			metrics.DelCCNP(&tt.args.cnp)

			assert.Equalf(t, tt.want.wantMetrics.npCCNPIngested, metrics.NPCCNPIngested.WithLabelValues(actionAdd).Get(), "NPCCNPIngested different")
			assert.Equalf(t, tt.want.wantMetrics.npCCNPIngested, metrics.NPCCNPIngested.WithLabelValues(actionDel).Get(), "NPCCNPIngested different")

		})
	}
}

func TestClusterMesh(t *testing.T) {
	type testCase struct {
		name        string
		mode        string
		maxClusters string
	}
	var tests []testCase
	for _, mode := range defaultClusterMeshMode {
		for _, maxClusters := range defaultClusterMeshMaxConnectedClusters {
			tests = append(tests, testCase{
				name:        fmt.Sprintf("ClusterMesh %s - %s", mode, maxClusters),
				mode:        mode,
				maxClusters: maxClusters,
			})
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Check that only the expected mode's counter is incremented
			for _, mode := range defaultClusterMeshMode {
				for _, maxClusters := range defaultClusterMeshMaxConnectedClusters {

					metrics := NewMetrics(true)
					metrics.AddClusterMeshConfig(tt.mode, tt.maxClusters)

					counter, err := metrics.ACLBClusterMeshEnabled.GetMetricWithLabelValues(mode, maxClusters)
					require.NoError(t, err)

					counterValue := counter.Get()
					if mode == tt.mode &&
						maxClusters == tt.maxClusters {
						assert.Equal(t, float64(1), counterValue, "Expected mode %s - %s to be incremented", mode, maxClusters)
					} else {
						assert.Equal(t, float64(0), counterValue, "Expected mode %s - %s to remain at 0", mode, maxClusters)
					}
					metrics.DelClusterMeshConfig(tt.mode, tt.maxClusters)

					counterValue = counter.Get()
					assert.Equal(t, float64(0), counterValue, "Expected mode %s - %s to remain at 0", mode, maxClusters)
				}
			}
		})
	}
}
