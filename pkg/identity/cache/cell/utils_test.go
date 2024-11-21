// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"testing"

	"github.com/cilium/cilium/pkg/option"
)

func TestNetPolicySystemIsEnabled(t *testing.T) {
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

			enablePolicy: option.NeverEnforce,
			disableCEP:   true,
			idAllocMode:  option.IdentityAllocationModeCRD,
		},
		{
			description: "enabled_all",
			want:        true,

			enablePolicy:    option.AlwaysEnforce,
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

			enablePolicy:    option.NeverEnforce,
			enableK8sPolicy: true,
			disableCEP:      true,
		},
		{
			description: "enabled_only_cnp_on",
			want:        true,

			enablePolicy: option.NeverEnforce,
			enableCNP:    true,
			disableCEP:   true,
		},
		{
			description: "enabled_only_ccnp_on",
			want:        true,

			enablePolicy: option.NeverEnforce,
			enableCCNP:   true,
			disableCEP:   true,
		},
		{
			description: "enabled_only_cep_crd_on",
			want:        true,

			enablePolicy: option.NeverEnforce,
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
		cfg := &option.DaemonConfig{
			EnablePolicy:                         tc.enablePolicy,
			EnableK8sNetworkPolicy:               tc.enableK8sPolicy,
			EnableCiliumNetworkPolicy:            tc.enableCNP,
			EnableCiliumClusterwideNetworkPolicy: tc.enableCCNP,
			DisableCiliumEndpointCRD:             tc.disableCEP,
			IdentityAllocationMode:               tc.idAllocMode,
		}

		t.Run(tc.description, func(t *testing.T) {
			if got := netPolicySystemIsEnabled(cfg); got != tc.want {
				t.Errorf("policy enabled = %t, want = %t", got, tc.want)
			}
		})
	}
}
