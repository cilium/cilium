// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"testing"
)

func TestNetworkPolicyEnabled(t *testing.T) {
	type testCase struct {
		description string
		want        bool

		enablePolicy    string
		enableK8sPolicy bool
		enableCNP       bool
		enableCCNP      bool
		disableCEP      bool
		idAllocMode     string
	}

	tcs := []testCase{
		{
			description: "disabled",
			want:        false,

			enablePolicy: NeverEnforce,
			disableCEP:   true,
			idAllocMode:  IdentityAllocationModeCRD,
		},
		{
			description: "enabled_all",
			want:        true,

			enablePolicy:    AlwaysEnforce,
			enableK8sPolicy: true,
			enableCNP:       true,
			enableCCNP:      true,
			disableCEP:      false,
		},
		{
			description: "enabled_only_policy_not_never",
			want:        true,

			enablePolicy: "test",
			disableCEP:   true,
		},
		{
			description: "enabled_only_k8s_np_on",
			want:        true,

			enablePolicy:    NeverEnforce,
			enableK8sPolicy: true,
			disableCEP:      true,
		},
		{
			description: "enabled_only_cnp_on",
			want:        true,

			enablePolicy: NeverEnforce,
			enableCNP:    true,
			disableCEP:   true,
		},
		{
			description: "enabled_only_ccnp_on",
			want:        true,

			enablePolicy: NeverEnforce,
			enableCCNP:   true,
			disableCEP:   true,
		},
		{
			description: "enabled_only_cep_crd_on",
			want:        true,

			enablePolicy: NeverEnforce,
			disableCEP:   false,
		},
		{
			description: "enabled_only_id_alloc_not_crd",
			want:        true,

			idAllocMode: "test",
			disableCEP:  false,
		},
	}

	for _, tc := range tcs {
		cfg := &DaemonConfig{
			EnablePolicy:                         tc.enablePolicy,
			EnableK8sNetworkPolicy:               tc.enableK8sPolicy,
			EnableCiliumNetworkPolicy:            tc.enableCNP,
			EnableCiliumClusterwideNetworkPolicy: tc.enableCCNP,
			DisableCiliumEndpointCRD:             tc.disableCEP,
			IdentityAllocationMode:               tc.idAllocMode,
		}

		t.Run(tc.description, func(t *testing.T) {
			if got := NetworkPolicyEnabled(cfg); got != tc.want {
				t.Errorf("policy enabled = %t, want = %t", got, tc.want)
			}
		})
	}
}
