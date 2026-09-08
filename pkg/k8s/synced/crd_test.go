// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"testing"

	"github.com/stretchr/testify/require"

	bgpConfig "github.com/cilium/cilium/pkg/bgp/config"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

func TestAgentCRDResourceNamesIPAMMode(t *testing.T) {
	originalIPAM := option.Config.IPAM
	t.Cleanup(func() { option.Config.IPAM = originalIPAM })

	for _, tc := range []struct {
		name          string
		ipam          string
		expectsIPPool bool
	}{
		{
			name:          "multi-pool",
			ipam:          ipamOption.IPAMMultiPool,
			expectsIPPool: true,
		},
		{
			name: "other IPAM modes",
			ipam: ipamOption.IPAMKubernetes,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			option.Config.IPAM = tc.ipam
			names := agentCRDResourceNames(bgpConfig.BGPConfig{})
			if tc.expectsIPPool {
				require.Contains(t, names, CRDResourceName(v2alpha1.CPIPName))
			} else {
				require.NotContains(t, names, CRDResourceName(v2alpha1.CPIPName))
			}
		})
	}
}

func TestAllCiliumCRDResourceNamesIncludesPodIPPool(t *testing.T) {
	originalIPAM := option.Config.IPAM
	t.Cleanup(func() { option.Config.IPAM = originalIPAM })

	for _, ipam := range []string{ipamOption.IPAMKubernetes, ipamOption.IPAMMultiPool} {
		option.Config.IPAM = ipam
		require.Contains(t, AllCiliumCRDResourceNames(bgpConfig.BGPConfig{}), CRDResourceName(v2alpha1.CPIPName))
	}
}
