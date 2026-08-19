// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestDeriveVPCCIDRs(t *testing.T) {
	t.Run("returns primary VPC CIDR from first ENI", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				VPC: awsTypes.AwsVPC{
					PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/16")),
				},
			},
		}
		primaryCIDR, secondaryCIDRs := deriveVPCCIDRs(node)
		require.Equal(t, netip.MustParsePrefix("10.0.0.0/16"), primaryCIDR)
		require.Empty(t, secondaryCIDRs)
	})

	t.Run("returns the secondary VPC CIDR associations", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				VPC: awsTypes.AwsVPC{
					PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.128.0/19")),
					CIDRs:       prefixes("100.64.0.0/16"),
				},
			},
		}
		primaryCIDR, secondaryCIDRs := deriveVPCCIDRs(node)
		require.Equal(t, netip.MustParsePrefix("10.1.128.0/19"), primaryCIDR)
		require.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, secondaryCIDRs)
	})

	t.Run("returns zero when no ENIs", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		primaryCIDR, _ := deriveVPCCIDRs(node)
		require.False(t, primaryCIDR.IsValid())
	})

	t.Run("returns zero when VPC CIDR is empty", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				VPC: awsTypes.AwsVPC{},
			},
		}
		primaryCIDR, _ := deriveVPCCIDRs(node)
		require.False(t, primaryCIDR.IsValid())
	})
}

func TestAutoDetectNativeRoutingCIDR(t *testing.T) {
	t.Run("auto-detects VPC CIDR when not configured", func(t *testing.T) {
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		primaryCIDR := netip.MustParsePrefix("10.0.0.0/16")
		conf := &option.DaemonConfig{}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, primaryCIDR, nil, localNodeStore, conf))

		localNode, err := localNodeStore.Get(context.Background())
		require.NoError(t, err)
		require.True(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
		require.Equal(t, "10.0.0.0/16", localNode.Local.IPv4NativeRoutingCIDR.String())
	})

	t.Run("does not overwrite when already configured", func(t *testing.T) {
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		primaryCIDR := netip.MustParsePrefix("10.0.0.0/16")
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, primaryCIDR, nil, localNodeStore, conf))

		localNode, err := localNodeStore.Get(context.Background())
		require.NoError(t, err)
		// Should NOT have been written since the config already has a value.
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("accepts a native routing CIDR that is a subnet of the VPC CIDR", func(t *testing.T) {
		// Regression test: a native routing CIDR that is a subset of the VPC
		// CIDR (e.g. a single availability-zone subnet) is a valid, supported
		// configuration. It must not be rejected.
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		primaryCIDR := netip.MustParsePrefix("192.168.0.0/16")
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("192.168.64.0/19"),
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, primaryCIDR, nil, localNodeStore, conf))

		localNode, err := localNodeStore.Get(context.Background())
		require.NoError(t, err)
		// Should NOT have been written since the config already has a value.
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("accepts a native routing CIDR matching a secondary VPC CIDR association", func(t *testing.T) {
		// Regression test: pod subnets are commonly carved out of a secondary
		// VPC CIDR association rather than the primary CIDR.
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		primaryCIDR := netip.MustParsePrefix("10.1.128.0/19")
		secondaryCIDRs := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("100.64.0.0/16"),
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, primaryCIDR, secondaryCIDRs, localNodeStore, conf))

		localNode, err := localNodeStore.Get(context.Background())
		require.NoError(t, err)
		// Should NOT have been written since the config already has a value.
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("rejects a native routing CIDR that overlaps no VPC CIDR", func(t *testing.T) {
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		primaryCIDR := netip.MustParsePrefix("10.1.128.0/19")
		secondaryCIDRs := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("192.168.0.0/16"),
		}
		require.Error(t, autoDetectNativeRoutingCIDR(logger, primaryCIDR, secondaryCIDRs, localNodeStore, conf))
	})
}
