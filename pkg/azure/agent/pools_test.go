// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestPoolAccessorFromResource(t *testing.T) {
	existing := ipamTypes.IPAMPoolSpec{
		Requested: []ipamTypes.IPAMPoolRequest{
			{
				Pool: defaults.IPAMDefaultIPPool,
				Needed: ipamTypes.IPAMPoolDemand{
					IPv4Addrs: 4,
				},
			},
		},
		Allocated: []ipamTypes.IPAMPoolAllocation{
			{
				Pool:  defaults.IPAMDefaultIPPool,
				CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.1/32"))},
			},
		},
	}

	t.Run("preserves pools until interface status is ready", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Spec.IPAM.Pools = existing

		result := poolAccessor.FromResource(node)
		require.True(t, existing.DeepEqual(&result))
	})

	t.Run("withdraws addresses when published status has none available", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Spec.IPAM.Pools = existing
		node.Status.Azure.Interfaces = []azureTypes.AzureInterface{
			{
				Addresses: []azureTypes.AzureAddress{
					{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")), State: "updating"},
					{State: azureTypes.StateSucceeded},
				},
			},
		}

		result := poolAccessor.FromResource(node)
		require.Equal(t, existing.Requested, result.Requested)
		require.Len(t, result.Allocated, 1)
		require.Equal(t, defaults.IPAMDefaultIPPool, result.Allocated[0].Pool)
		require.True(t, result.Allocated[0].AllowFirstIP)
		require.True(t, result.Allocated[0].AllowLastIP)
		require.Empty(t, result.Allocated[0].CIDRs)
	})

	t.Run("publishes successful addresses as host prefixes", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Spec.IPAM.Pools = existing
		node.Status.Azure.Interfaces = []azureTypes.AzureInterface{
			{
				Addresses: []azureTypes.AzureAddress{
					{IP: iputil.AddrFrom(netip.MustParseAddr("2001:db8::2")), State: azureTypes.StateSucceeded},
					{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")), State: "updating"},
					{IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")), State: azureTypes.StateSucceeded},
					{State: azureTypes.StateSucceeded},
				},
			},
		}

		result := poolAccessor.FromResource(node)
		require.Equal(t, existing.Requested, result.Requested)
		require.Len(t, result.Allocated, 1)
		require.Equal(t, defaults.IPAMDefaultIPPool, result.Allocated[0].Pool)
		require.True(t, result.Allocated[0].AllowFirstIP)
		require.True(t, result.Allocated[0].AllowLastIP)
		require.Equal(t, []iputil.Prefix{
			iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.2/32")),
			iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::2/128")),
		}, result.Allocated[0].CIDRs)
	})
}

func TestPoolAccessorToResource(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	spec := ipamTypes.IPAMPoolSpec{
		Requested: []ipamTypes.IPAMPoolRequest{{Pool: defaults.IPAMDefaultIPPool}},
	}

	require.True(t, poolAccessor.ToResource(node, spec))
	require.True(t, spec.DeepEqual(&node.Spec.IPAM.Pools))
	require.False(t, poolAccessor.ToResource(node, spec))
}
