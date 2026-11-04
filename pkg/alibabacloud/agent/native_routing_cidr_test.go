// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestAutoDetectIPv4NativeRoutingCIDR(t *testing.T) {
	const vpcCIDR = "10.10.0.0/16"

	newNode := func(nativeCIDR, vpcCIDR string, secondaryCIDRs ...string) (*ciliumv2.CiliumNode, *option.DaemonConfig) {
		eni := alibabaCloudTypes.ENI{NetworkInterfaceID: "eni-1"}
		for _, cidr := range secondaryCIDRs {
			eni.VPC.SecondaryCIDRs = append(eni.VPC.SecondaryCIDRs, iputil.PrefixFrom(netip.MustParsePrefix(cidr)))
		}

		spec := alibabaCloudTypes.Spec{}
		if vpcCIDR != "" {
			spec.CIDRBlock = iputil.PrefixFrom(netip.MustParsePrefix(vpcCIDR))
		}

		conf := &option.DaemonConfig{}
		if nativeCIDR != "" {
			conf.IPv4NativeRoutingCIDR = netip.MustParsePrefix(nativeCIDR)
		}

		return &ciliumv2.CiliumNode{
			Spec:   ciliumv2.NodeSpec{AlibabaCloud: spec},
			Status: ciliumv2.NodeStatus{AlibabaCloud: alibabaCloudTypes.ENIStatus{ENIs: map[string]alibabaCloudTypes.ENI{"eni-1": eni}}},
		}, conf
	}
	check := func(t *testing.T, localNodeStore *node.LocalNodeStore, nativeCIDR, vpcCIDR string, secondaryCIDRs ...string) bool {
		cn, conf := newNode(nativeCIDR, vpcCIDR, secondaryCIDRs...)
		primary, secondary := deriveVpcCIDRs(cn)
		if !primary.IsValid() {
			return false
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(hivetest.Logger(t), primary, secondary, localNodeStore, conf))
		return true
	}

	t.Run("accepts a native routing CIDR that is a subnet of the VPC CIDR", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.True(t, check(t, localNodeStore, "10.10.64.0/19", vpcCIDR))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		// Should NOT have been written since the config already has a value.
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("accepts a native routing CIDR that is a supernet of the VPC CIDR", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.True(t, check(t, localNodeStore, "10.0.0.0/8", vpcCIDR))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("accepts a native routing CIDR that only overlaps a secondary VPC CIDR", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.True(t, check(t, localNodeStore, "172.16.32.0/20", vpcCIDR, "172.16.0.0/12"))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("uses the autodetected primary CIDR when unset", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.True(t, check(t, localNodeStore, "", vpcCIDR))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		require.Equal(t, vpcCIDR, localNode.Local.IPv4NativeRoutingCIDR.String())
	})

	t.Run("reports failure while the VPC CIDR is unknown", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.False(t, check(t, localNodeStore, "", ""))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})
}

func TestNativeRoutingPodSubnets(t *testing.T) {
	primary := netip.MustParsePrefix("10.10.0.0/16")
	secondary := netip.MustParsePrefix("172.16.0.0/12")
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	conf := &option.DaemonConfig{
		IPv4NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
		IPv6NativeRoutingCIDR: netip.MustParsePrefix("2001:db8::/64"),
	}
	require.NoError(t, autoDetectNativeRoutingCIDR(hivetest.Logger(t), primary, []netip.Prefix{secondary}, localNodeStore, conf))
	ln, err := localNodeStore.Get(t.Context())
	require.NoError(t, err)
	require.ElementsMatch(t, []iputil.Prefix{iputil.PrefixFrom(conf.IPv4NativeRoutingCIDR), iputil.PrefixFrom(secondary)}, ln.Local.IPv4PodSubnets)
	require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(conf.IPv6NativeRoutingCIDR)}, ln.Local.IPv6PodSubnets)

	conf.IPv4NativeRoutingCIDR = netip.MustParsePrefix("192.168.0.0/16")
	require.ErrorContains(t, autoDetectNativeRoutingCIDR(hivetest.Logger(t), primary, []netip.Prefix{secondary}, localNodeStore, conf), "none of the AlibabaCloud VPC CIDRs overlaps")
}

func TestDeriveVpcCIDRs(t *testing.T) {
	cn := &ciliumv2.CiliumNode{}
	cn.Spec.AlibabaCloud.CIDRBlock = iputil.PrefixFrom(netip.MustParsePrefix("10.10.1.1/16"))
	primary, secondary := deriveVpcCIDRs(cn)
	require.False(t, primary.IsValid(), "wait for operator ENI status")
	require.Empty(t, secondary)
	cn.Status.AlibabaCloud.ENIs = map[string]alibabaCloudTypes.ENI{"eni-1": {VPC: alibabaCloudTypes.VPC{SecondaryCIDRs: []iputil.Prefix{
		{}, iputil.PrefixFrom(netip.MustParsePrefix("172.16.1.1/12")),
	}}}}
	primary, secondary = deriveVpcCIDRs(cn)
	require.Equal(t, netip.MustParsePrefix("10.10.0.0/16"), primary)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}, secondary)
}

func TestProviderWaitReady(t *testing.T) {
	p := &provider{}
	require.ErrorContains(t, p.WaitReady(t.Context()), "before Initialize")
	for _, wantErr := range []error{nil, errors.New("invalid native routing CIDR")} {
		ready := make(chan error, 1)
		ready <- wantErr
		p.nativeRoutingCIDRReady = ready
		require.ErrorIs(t, p.WaitReady(t.Context()), wantErr)
	}
	p.nativeRoutingCIDRReady = make(chan error)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, p.WaitReady(ctx), context.Canceled)
}
