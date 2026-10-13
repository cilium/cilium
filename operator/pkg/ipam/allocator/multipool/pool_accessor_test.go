// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestSinglePoolAccessor(t *testing.T) {
	cidr := func(s string) []iputil.Prefix {
		return []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix(s))}
	}
	defaultReq := types.IPAMPoolRequest{Pool: "default", Needed: types.IPAMPoolDemand{IPv6Addrs: 8}}
	egressReq := types.IPAMPoolRequest{Pool: "egress", Needed: types.IPAMPoolDemand{IPv4Addrs: 8}}
	defaultAlloc := types.IPAMPoolAllocation{Pool: "default", CIDRs: cidr("2001:db8::/80")}
	egressAlloc := types.IPAMPoolAllocation{Pool: "egress", CIDRs: cidr("100.64.0.0/24")}

	accessor := SinglePoolAccessor("egress")

	t.Run("reads only the pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools = types.IPAMPoolSpec{
			Requested: []types.IPAMPoolRequest{defaultReq, egressReq},
			Allocated: []types.IPAMPoolAllocation{defaultAlloc, egressAlloc},
		}

		spec := accessor.FromResource(cn)
		require.Equal(t, []types.IPAMPoolRequest{egressReq}, spec.Requested)
		require.Equal(t, []types.IPAMPoolAllocation{egressAlloc}, spec.Allocated)
	})

	t.Run("writes only the pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools = types.IPAMPoolSpec{
			Requested: []types.IPAMPoolRequest{defaultReq, egressReq},
			Allocated: []types.IPAMPoolAllocation{defaultAlloc},
		}

		// The other pools of the spec handed back are ignored.
		changed := accessor.ToResource(cn, types.IPAMPoolSpec{
			Requested: []types.IPAMPoolRequest{egressReq},
			Allocated: []types.IPAMPoolAllocation{egressAlloc, {Pool: "default"}},
		})
		require.True(t, changed)
		require.Equal(t, []types.IPAMPoolRequest{defaultReq, egressReq}, cn.Spec.IPAM.Pools.Requested)
		require.Equal(t, []types.IPAMPoolAllocation{defaultAlloc, egressAlloc}, cn.Spec.IPAM.Pools.Allocated)

		// Writing the same allocation again is not a change.
		require.False(t, accessor.ToResource(cn, accessor.FromResource(cn)))
	})

	t.Run("releases the pool", func(t *testing.T) {
		cn := &v2.CiliumNode{}
		cn.Spec.IPAM.Pools = types.IPAMPoolSpec{
			Allocated: []types.IPAMPoolAllocation{egressAlloc, defaultAlloc},
		}

		require.True(t, accessor.ToResource(cn, types.IPAMPoolSpec{}))
		require.Equal(t, []types.IPAMPoolAllocation{defaultAlloc}, cn.Spec.IPAM.Pools.Allocated)
	})
}
