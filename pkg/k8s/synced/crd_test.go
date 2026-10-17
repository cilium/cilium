// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"testing"

	"github.com/stretchr/testify/assert"

	bgpConfig "github.com/cilium/cilium/pkg/bgp/config"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/option"
)

// TestAgentCRDResourceNamesPodIPPool asserts that the agent only blocks its
// startup on the CiliumPodIPPool CRD in multi-pool IPAM mode, while the
// operator keeps registering it in every mode.
func TestAgentCRDResourceNamesPodIPPool(t *testing.T) {
	cpip := CRDResourceName(v2alpha1.CPIPName)

	for _, ipamMode := range []string{
		ipamOption.IPAMKubernetes,
		ipamOption.IPAMCRD,
		ipamOption.IPAMENI,
		ipamOption.IPAMAzure,
		ipamOption.IPAMClusterPool,
		ipamOption.IPAMAlibabaCloud,
		ipamOption.IPAMDelegatedPlugin,
		ipamOption.IPAMMultiPool,
	} {
		t.Run(ipamMode, func(t *testing.T) {
			prevIPAM := option.Config.IPAM
			option.Config.IPAM = ipamMode
			t.Cleanup(func() { option.Config.IPAM = prevIPAM })

			agent := AgentCRDResourceNames(bgpConfig.DefaultConfig)
			if ipamMode == ipamOption.IPAMMultiPool {
				assert.Contains(t, agent, cpip,
					"multi-pool IPAM reads CiliumPodIPPool, so the agent must wait for the CRD")
			} else {
				assert.NotContains(t, agent, cpip,
					"CiliumPodIPPool is unused in %s IPAM mode, so the agent must not wait for the CRD", ipamMode)
			}

			// The operator creates its CRDs from this list, so CiliumPodIPPool
			// has to appear exactly once regardless of the IPAM mode.
			all := AllCiliumCRDResourceNames(bgpConfig.DefaultConfig)
			assert.Equal(t, 1, countOccurrences(all, cpip),
				"CiliumPodIPPool must be listed exactly once in %v", all)
		})
	}
}

func countOccurrences(haystack []string, needle string) int {
	var n int
	for _, s := range haystack {
		if s == needle {
			n++
		}
	}
	return n
}
