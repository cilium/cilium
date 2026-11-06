// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/alibabacloud/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestIPv6Prefixes(t *testing.T) {
	subnet := &ipamTypes.Subnet{
		ID: "vsw-1", CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		IPv6CIDR: netip.MustParsePrefix("fd00:0:0:1::/64"), AvailableAddresses: 100,
	}
	api := NewAPI([]*ipamTypes.Subnet{subnet}, nil, nil)

	id, eni, err := api.CreateNetworkInterface(t.Context(), 2, "vsw-1", nil, nil, true)
	require.NoError(t, err)
	require.Len(t, eni.PrivateIPSets, 3)
	require.Len(t, eni.IPv6Prefixes, 1)
	firstPrefix := eni.IPv6Prefixes[0]
	require.True(t, firstPrefix.Addr().Is6())
	require.Equal(t, 80, firstPrefix.Bits())
	require.NoError(t, api.AttachNetworkInterface(t.Context(), "i-1", id))
	require.NoError(t, api.AssignENIIPv6Prefix(t.Context(), id))

	instance, err := api.GetInstance(t.Context(), nil, ipamTypes.SubnetMap{"vsw-1": subnet}, "i-1")
	require.NoError(t, err)
	updated := instance.Interfaces[id].(*types.ENI)
	require.Len(t, updated.IPv6Prefixes, 2)
	require.Equal(t, firstPrefix, updated.IPv6Prefixes[0])
	require.NotEqual(t, firstPrefix, updated.IPv6Prefixes[1])
	require.Equal(t, eni.PrivateIPSets, updated.PrivateIPSets)
	require.Equal(t, subnet.IPv6CIDR, updated.VSwitch.IPv6CIDRBlock.Prefix)

	_, ipv4ENI, err := api.CreateNetworkInterface(t.Context(), 0, "vsw-1", nil, nil, false)
	require.NoError(t, err)
	require.Empty(t, ipv4ENI.IPv6Prefixes)
	require.Len(t, ipv4ENI.PrivateIPSets, 1)
	subnets, err := api.GetVSwitches(t.Context())
	require.NoError(t, err)
	require.Equal(t, 96, subnets["vsw-1"].AvailableAddresses)
	require.Error(t, api.AssignENIIPv6Prefix(t.Context(), "unknown-eni"))
}
