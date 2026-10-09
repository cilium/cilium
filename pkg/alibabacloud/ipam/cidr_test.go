// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/operator/pkg/ipam/nodemanager"
	"github.com/cilium/cilium/pkg/alibabacloud/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestAttachedCIDRsAndPrepareRelease(t *testing.T) {
	address := func(s string, primary bool) types.PrivateIPSet {
		return types.PrivateIPSet{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr(s)), Primary: primary}
	}
	n := &Node{enis: map[string]types.ENI{
		"host": {Type: types.ENITypePrimary, PrivateIPSets: []types.PrivateIPSet{address("10.0.0.1", true), address("10.0.0.2", false)}},
		"eni-1": {
			Type:             types.ENITypeSecondary,
			PrimaryIPAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")),
			VSwitch:          types.VSwitch{VSwitchID: "vsw-1"},
			// Also protect the primary address if its per-address flag is absent.
			PrivateIPSets: []types.PrivateIPSet{address("10.0.0.3", false), address("10.0.0.4", false), address("10.0.0.5", true), {}, address("2001:db8::1", false)},
		},
		"eni-2": {Type: types.ENITypeSecondary, VSwitch: types.VSwitch{VSwitchID: "vsw-2"}, PrivateIPSets: []types.PrivateIPSet{address("10.0.0.6", false), address("10.0.0.7", false)}},
	}}
	prefixes := func(addrs ...string) []netip.Prefix {
		var result []netip.Prefix
		for _, addr := range addrs {
			result = append(result, netip.MustParsePrefix(addr))
		}
		return result
	}
	require.ElementsMatch(t, prefixes("10.0.0.3/32", "10.0.0.4/32", "10.0.0.5/32", "10.0.0.6/32", "10.0.0.7/32"), n.GetAttachedCIDRs())
	require.Empty(t, n.PrepareCIDRRelease(nil))
	actions := n.PrepareCIDRRelease(prefixes("10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/32", "10.0.0.4/32", "10.0.0.5/32", "10.0.0.6/32", "10.0.0.99/32", "10.0.0.0/24", "2001:db8::1/128"))
	require.ElementsMatch(t, []*nodemanager.ReleaseAction{
		{InterfaceID: "eni-1", PoolID: ipamTypes.PoolID("vsw-1"), CIDRsToRelease: prefixes("10.0.0.4/32")},
		{InterfaceID: "eni-2", PoolID: ipamTypes.PoolID("vsw-2"), CIDRsToRelease: prefixes("10.0.0.6/32")},
	}, actions)
}

type releaseAPIMock struct {
	AlibabaCloudAPI
	calls     int
	eniID     string
	addresses []string
	err       error
}

func (a *releaseAPIMock) UnassignPrivateIPAddresses(_ context.Context, eniID string, addresses []string) error {
	a.calls++
	a.eniID = eniID
	a.addresses = addresses
	return a.err
}

func TestReleaseCIDRs(t *testing.T) {
	wantErr := errors.New("ECS release failed")
	for _, fail := range []bool{false, true} {
		api := &releaseAPIMock{}
		if fail {
			api.err = wantErr
		}
		n := &Node{manager: &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}}
		action := &nodemanager.ReleaseAction{
			InterfaceID:    "eni-1",
			CIDRsToRelease: []netip.Prefix{netip.MustParsePrefix("10.0.0.4/32"), netip.MustParsePrefix("10.0.0.5/32")},
		}
		// The node manager can narrow the action after preparation. Never use
		// IPsToRelease from the old CRD protocol instead of the filtered CIDRs.
		action.IPsToRelease = []string{"10.0.0.99"}
		released, err := n.ReleaseCIDRs(t.Context(), action)
		if fail {
			require.ErrorIs(t, err, wantErr)
			require.Empty(t, released)
		} else {
			require.NoError(t, err)
			require.Equal(t, action.CIDRsToRelease, released)
		}
		require.Equal(t, "eni-1", api.eniID)
		require.Equal(t, []string{"10.0.0.4", "10.0.0.5"}, api.addresses)
	}
	for _, prefix := range []string{"10.0.0.0/24", "2001:db8::1/128"} {
		api := &releaseAPIMock{}
		n := &Node{manager: &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}}
		_, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{CIDRsToRelease: []netip.Prefix{netip.MustParsePrefix(prefix)}})
		require.Error(t, err)
		require.Zero(t, api.calls)
	}
	api := &releaseAPIMock{}
	n := &Node{manager: &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}}
	released, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{})
	require.NoError(t, err)
	require.Empty(t, released)
	require.Zero(t, api.calls)
}

func TestReleaseCIDRsUpdatesPublishedStatus(t *testing.T) {
	for _, fail := range []bool{false, true} {
		api := &releaseAPIMock{}
		if fail {
			api.err = errors.New("release failed")
		}
		manager := &InstancesManager{api: api, instances: ipamTypes.NewInstanceMap()}
		eni := &types.ENI{
			NetworkInterfaceID: "eni-1",
			Type:               types.ENITypeSecondary,
			PrivateIPSets: []types.PrivateIPSet{
				{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")), Primary: true},
				{PrivateIpAddress: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4"))},
			},
		}
		manager.UpdateENI("i-1", eni)
		cn := newCiliumNode("node1", "i-1", "ecs.g7ne.large", "cn-hangzhou-i", "vpc-1")
		// The node manager has not yet bound its CiliumNode when CreateNode is called.
		n := manager.CreateNode(cn, &nodemanager.Node{}).(*Node)
		require.Equal(t, "i-1", n.instanceID)
		_, err := n.ReleaseCIDRs(t.Context(), &nodemanager.ReleaseAction{
			InterfaceID: "eni-1", CIDRsToRelease: []netip.Prefix{netip.MustParsePrefix("10.0.0.4/32")},
		})
		n.PopulateStatusFields(cn)
		if fail {
			require.Error(t, err)
			require.Equal(t, eni.PrivateIPSets, cn.Status.AlibabaCloud.ENIs["eni-1"].PrivateIPSets)
		} else {
			require.NoError(t, err)
			require.Equal(t, eni.PrivateIPSets[:1], cn.Status.AlibabaCloud.ENIs["eni-1"].PrivateIPSets)
		}
		require.Len(t, eni.PrivateIPSets, 2, "cache updates must not mutate existing snapshots")
	}
}
