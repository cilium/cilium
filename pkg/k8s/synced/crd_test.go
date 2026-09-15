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
	for _, tc := range []struct {
		ipam          string
		expectsIPPool bool
	}{
		{
			ipam:          ipamOption.IPAMMultiPool,
			expectsIPPool: true,
		},
		{ipam: ipamOption.IPAMKubernetes},
		{ipam: ipamOption.IPAMCRD},
		{ipam: ipamOption.IPAMENI},
		{ipam: ipamOption.IPAMAzure},
		{ipam: ipamOption.IPAMClusterPool},
		{ipam: ipamOption.IPAMAlibabaCloud},
		{ipam: ipamOption.IPAMDelegatedPlugin},
	} {
		t.Run(tc.ipam, func(t *testing.T) {
			originalIPAM := option.Config.IPAM
			t.Cleanup(func() { option.Config.IPAM = originalIPAM })
			option.Config.IPAM = tc.ipam
			names := agentCRDResourceNames(bgpConfig.DefaultConfig)
			if tc.expectsIPPool {
				require.Contains(t, names, CRDResourceName(v2alpha1.CPIPName))
			} else {
				require.NotContains(t, names, CRDResourceName(v2alpha1.CPIPName))
			}
		})
	}
}

func TestAllCiliumCRDResourceNamesIncludesPodIPPool(t *testing.T) {
	for _, ipam := range []string{
		ipamOption.IPAMKubernetes,
		ipamOption.IPAMCRD,
		ipamOption.IPAMENI,
		ipamOption.IPAMAzure,
		ipamOption.IPAMClusterPool,
		ipamOption.IPAMAlibabaCloud,
		ipamOption.IPAMDelegatedPlugin,
		ipamOption.IPAMMultiPool,
	} {
		t.Run(ipam, func(t *testing.T) {
			originalIPAM := option.Config.IPAM
			t.Cleanup(func() { option.Config.IPAM = originalIPAM })
			option.Config.IPAM = ipam
			names := AllCiliumCRDResourceNames(bgpConfig.DefaultConfig)
			require.Contains(t, names, CRDResourceName(v2alpha1.CPIPName))
			n := 0
			for _, name := range names {
				if name == CRDResourceName(v2alpha1.CPIPName) {
					n++
				}
			}
			require.Equal(t, 1, n)
		})
	}
}
