// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestPoolAccessor(t *testing.T) {
	cn := &ciliumv2.CiliumNode{}
	existing := ipamTypes.IPAMPoolSpec{
		Requested: []ipamTypes.IPAMPoolRequest{{Pool: defaults.IPAMDefaultIPPool, Needed: ipamTypes.IPAMPoolDemand{IPv4Addrs: 4}}},
		Allocated: []ipamTypes.IPAMPoolAllocation{{Pool: defaults.IPAMDefaultIPPool, CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.9/32"))}}},
	}
	require.True(t, poolAccessor.ToResource(cn, existing))
	require.False(t, poolAccessor.ToResource(cn, existing))
	require.Equal(t, existing, poolAccessor.FromResource(cn), "preserve restored pools until ENI status is available")

	cn.Status.AlibabaCloud.ENIs = map[string]alibabaCloudTypes.ENI{
		"primary": {Type: alibabaCloudTypes.ENITypePrimary, PrivateIPSets: []alibabaCloudTypes.PrivateIPSet{
			{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")), Primary: true},
			{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.2"))},
		}},
		"secondary": {Type: alibabaCloudTypes.ENITypeSecondary, PrivateIPSets: []alibabaCloudTypes.PrivateIPSet{
			{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4"))},
			{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")), Primary: true},
			{},
			{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("2001:db8::1"))},
		}},
	}
	got := poolAccessor.FromResource(cn)
	require.Equal(t, existing.Requested, got.Requested)
	require.Equal(t, []ipamTypes.IPAMPoolAllocation{{
		Pool: defaults.IPAMDefaultIPPool, AllowFirstIP: true, AllowLastIP: true,
		CIDRs: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.3/32")), iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.4/32"))},
	}}, got.Allocated)
	require.Equal(t, existing, cn.Spec.IPAM.Pools, "reading status must not mutate the CiliumNode")

	delete(cn.Status.AlibabaCloud.ENIs, "secondary")
	got = poolAccessor.FromResource(cn)
	require.Len(t, got.Allocated, 1)
	require.Empty(t, got.Allocated[0].CIDRs, "withdraw stale allocations when no eligible addresses remain")
}
