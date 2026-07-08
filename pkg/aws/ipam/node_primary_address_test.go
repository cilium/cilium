// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

// TestForeachENIPrimaryAddressFiltering verifies that the per-node primary
// address policy is applied when iterating the shared EC2 inventory: the
// primary IP is stripped from an ENI's Addresses unless
// Spec.ENI.UsePrimaryAddress is set. The shared inventory itself must never be
// mutated by the filtering.
func TestForeachENIPrimaryAddressFiltering(t *testing.T) {
	instanceID := "i-000"
	primary := netip.MustParseAddr("10.0.0.1")
	secondary := netip.MustParseAddr("10.0.0.2")

	im := ipamTypes.NewInstanceMap()
	im.Update(instanceID, &types.ENI{
		ID: "eni-1",
		IP: iputil.AddrFrom(primary),
		Addresses: []iputil.Addr{
			iputil.AddrFrom(primary),
			iputil.AddrFrom(secondary),
		},
	})

	n := &Node{
		node:    &mockIPAMNode{instanceID: instanceID},
		k8sObj:  newCiliumNode("node1"),
		manager: &InstancesManager{instances: im},
	}

	collect := func(usePrimary bool) []netip.Addr {
		var got []netip.Addr
		n.foreachENI(usePrimary, func(e *types.ENI) error {
			for _, a := range e.Addresses {
				got = append(got, a.Addr)
			}
			return nil
		})
		return got
	}

	// UsePrimaryAddress disabled: the primary IP is not available for allocation.
	assert.ElementsMatch(t, []netip.Addr{secondary}, collect(false))

	// UsePrimaryAddress enabled: the primary IP is available for allocation.
	assert.ElementsMatch(t, []netip.Addr{primary, secondary}, collect(true))

	// Filtering must not mutate the shared inventory (ForeachInterface hands
	// out live data; foreachENI must operate on a fresh slice).
	iface, ok := im.GetInterface(instanceID, "eni-1")
	require.True(t, ok)
	eni, ok := iface.(*types.ENI)
	require.True(t, ok)
	assert.Len(t, eni.Addresses, 2, "shared inventory must retain the primary address")
}

// TestUsePrimaryAddress verifies the spec-backed accessor.
func TestUsePrimaryAddress(t *testing.T) {
	enabled := true
	disabled := false

	tests := []struct {
		name string
		spec *bool
		want bool
	}{
		{name: "unset defaults to false", spec: nil, want: false},
		{name: "explicitly false", spec: &disabled, want: false},
		{name: "explicitly true", spec: &enabled, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn := newCiliumNode("node1")
			cn.Spec.ENI.UsePrimaryAddress = tt.spec
			n := &Node{k8sObj: cn}
			assert.Equal(t, tt.want, n.usePrimaryAddress())
		})
	}
}
