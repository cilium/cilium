// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func defaultPoolDemand(ipv4, ipv6 int) []ipamTypes.IPAMPoolRequest {
	return []ipamTypes.IPAMPoolRequest{{
		Pool:   defaults.IPAMDefaultIPPool,
		Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: ipv4, IPv6Addrs: ipv6},
	}}
}

// TestSeedPoolRequest asserts that a CiliumNode is created with a demand for
// the families the agent uses, so that the operator treats it as a multi-pool
// node before the multi-pool manager writes the actual demand, and that an
// existing demand is left alone.
func TestSeedPoolRequest(t *testing.T) {
	tests := []struct {
		name        string
		ipv4, ipv6  bool
		preAllocate int
		existing    []ipamTypes.IPAMPoolRequest
		want        []ipamTypes.IPAMPoolRequest
	}{
		{
			name: "IPv6-only requests no IPv4",
			ipv6: true,
			want: defaultPoolDemand(0, defaults.IPAMPreAllocation),
		},
		{
			name: "IPv4-only requests no IPv6",
			ipv4: true,
			want: defaultPoolDemand(defaults.IPAMPreAllocation, 0),
		},
		{
			name: "dual-stack requests both",
			ipv4: true, ipv6: true,
			want: defaultPoolDemand(defaults.IPAMPreAllocation, defaults.IPAMPreAllocation),
		},
		{
			name: "no family requests nothing",
		},
		{
			name:        "uses the pre-allocate of the spec",
			ipv4:        true,
			preAllocate: 4,
			want:        defaultPoolDemand(4, 0),
		},
		{
			name:     "keeps the demand of the multi-pool manager",
			ipv6:     true,
			existing: defaultPoolDemand(0, 42),
			want:     defaultPoolDemand(0, 42),
		},
		{
			name: "adds the default pool next to other pools",
			ipv6: true,
			existing: []ipamTypes.IPAMPoolRequest{{
				Pool:   "other",
				Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 1},
			}},
			want: append([]ipamTypes.IPAMPoolRequest{{
				Pool:   "other",
				Needed: ipamTypes.IPAMPoolDemand{IPv6Addrs: 1},
			}}, defaultPoolDemand(0, defaults.IPAMPreAllocation)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var spec ciliumv2.NodeSpec
			spec.IPAM.PreAllocate = tt.preAllocate
			spec.IPAM.Pools.Requested = tt.existing

			SeedPoolRequest(&spec, tt.ipv4, tt.ipv6)

			require.Equal(t, tt.want, spec.IPAM.Pools.Requested)
		})
	}
}
