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
		vpc := deriveVPCCIDRs(node)
		require.Equal(t, netip.MustParsePrefix("10.0.0.0/16"), vpc.primary)
		require.Empty(t, vpc.secondary)
		require.Empty(t, vpc.ipv6)
		require.False(t, vpc.multipleVPCs)
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
		vpc := deriveVPCCIDRs(node)
		require.Equal(t, netip.MustParsePrefix("10.1.128.0/19"), vpc.primary)
		require.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, vpc.secondary)
	})

	t.Run("returns zero when no ENIs", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		vpc := deriveVPCCIDRs(node)
		require.False(t, vpc.primary.IsValid())
	})

	t.Run("returns zero when VPC CIDR is empty", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				VPC: awsTypes.AwsVPC{
					IPv6CIDRs: prefixes("2600:1f14:abcd:ef00::/56"),
				},
			},
		}
		require.Equal(t, vpcCIDRs{}, deriveVPCCIDRs(node))
	})

	t.Run("unions the IPv6 CIDRs of the ENIs of the selected VPC only", func(t *testing.T) {
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				VPC: awsTypes.AwsVPC{
					ID:          "vpc-1",
					PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("192.168.0.0/16")),
					IPv6CIDRs:   prefixes("2600:1f14:abcd:ef00::/56", "2600:1f14:1111:2200::1/56"),
				},
			},
			"eni-2": {
				// Same VPC, IPv6 metadata not populated yet.
				VPC: awsTypes.AwsVPC{
					ID:          "vpc-1",
					PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("192.168.0.0/16")),
				},
			},
			"eni-3": {
				// Same VPC, duplicate and additional association, plus an
				// IPv4 entry that must be ignored.
				VPC: awsTypes.AwsVPC{
					ID:        "vpc-1",
					IPv6CIDRs: prefixes("2600:1f14:abcd:ef00::/56", "2600:1f14:9999::/56", "10.0.0.0/8"),
				},
			},
			"eni-4": {
				// Another VPC, without a valid primary CIDR so it can never
				// be selected, whatever the map iteration order.
				VPC: awsTypes.AwsVPC{
					ID:        "vpc-2",
					IPv6CIDRs: prefixes("2a05:d018::/56"),
				},
			},
		}
		vpc := deriveVPCCIDRs(node)
		require.Equal(t, netip.MustParsePrefix("192.168.0.0/16"), vpc.primary)
		require.Equal(t, []netip.Prefix{
			netip.MustParsePrefix("2600:1f14:1111:2200::/56"),
			netip.MustParsePrefix("2600:1f14:9999::/56"),
			netip.MustParsePrefix("2600:1f14:abcd:ef00::/56"),
		}, vpc.ipv6)
		require.True(t, vpc.multipleVPCs)
	})
}

func TestAutoDetectNativeRoutingCIDR(t *testing.T) {
	t.Run("auto-detects VPC CIDR when not configured", func(t *testing.T) {
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		vpc := vpcCIDRs{primary: netip.MustParsePrefix("10.0.0.0/16")}
		conf := &option.DaemonConfig{}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, vpc, localNodeStore, conf))

		localNode, err := localNodeStore.Get(context.Background())
		require.NoError(t, err)
		require.True(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
		require.Equal(t, "10.0.0.0/16", localNode.Local.IPv4NativeRoutingCIDR.String())
	})

	t.Run("does not overwrite when already configured", func(t *testing.T) {
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		vpc := vpcCIDRs{primary: netip.MustParsePrefix("10.0.0.0/16")}
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, vpc, localNodeStore, conf))

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

		vpc := vpcCIDRs{primary: netip.MustParsePrefix("192.168.0.0/16")}
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("192.168.64.0/19"),
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, vpc, localNodeStore, conf))

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

		vpc := vpcCIDRs{
			primary:   netip.MustParsePrefix("10.1.128.0/19"),
			secondary: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")},
		}
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("100.64.0.0/16"),
		}
		require.NoError(t, autoDetectNativeRoutingCIDR(logger, vpc, localNodeStore, conf))

		localNode, err := localNodeStore.Get(context.Background())
		require.NoError(t, err)
		// Should NOT have been written since the config already has a value.
		require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
	})

	t.Run("rejects a native routing CIDR that overlaps no VPC CIDR", func(t *testing.T) {
		logger := hivetest.Logger(t)
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})

		vpc := vpcCIDRs{
			primary:   netip.MustParsePrefix("10.1.128.0/19"),
			secondary: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")},
		}
		conf := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("192.168.0.0/16"),
		}
		require.Error(t, autoDetectNativeRoutingCIDR(logger, vpc, localNodeStore, conf))
	})
}

func TestAutoDetectIPv6PodSubnets(t *testing.T) {
	vpc := vpcCIDRs{
		primary: netip.MustParsePrefix("192.168.0.0/16"),
		ipv6: []netip.Prefix{
			netip.MustParsePrefix("2600:1f14:1111:2200::/56"),
			netip.MustParsePrefix("2600:1f14:abcd:ef00::/56"),
		},
	}

	for _, tc := range []struct {
		name       string
		conf       *option.DaemonConfig
		expectedV6 []netip.Prefix
	}{
		{
			name:       "IPv6-only records the VPC IPv6 CIDRs",
			conf:       &option.DaemonConfig{EnableIPv6: true},
			expectedV6: vpc.ipv6,
		},
		{
			name:       "dual-stack records the VPC IPv6 CIDRs",
			conf:       &option.DaemonConfig{EnableIPv4: true, EnableIPv6: true},
			expectedV6: vpc.ipv6,
		},
		{
			name: "IPv4-only ignores the VPC IPv6 CIDRs",
			conf: &option.DaemonConfig{EnableIPv4: true},
		},
		{
			name: "a configured native routing CIDR contained in a VPC IPv6 CIDR coalesces",
			conf: &option.DaemonConfig{
				EnableIPv6:            true,
				IPv6NativeRoutingCIDR: netip.MustParsePrefix("2600:1f14:abcd:ef00::/64"),
			},
			expectedV6: vpc.ipv6,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
			require.NoError(t, autoDetectNativeRoutingCIDR(hivetest.Logger(t), vpc, localNodeStore, tc.conf))

			localNode, err := localNodeStore.Get(context.Background())
			require.NoError(t, err)
			require.Equal(t, []iputil.Prefix{iputil.PrefixFrom(vpc.primary)}, localNode.Local.IPv4PodSubnets)
			var v6 []netip.Prefix
			for _, p := range localNode.Local.IPv6PodSubnets {
				v6 = append(v6, p.Prefix)
			}
			require.Equal(t, tc.expectedV6, v6)
			// The IPv6 native routing CIDR is never autodetected.
			require.False(t, localNode.Local.IPv6NativeRoutingCIDR.IsValid())
		})
	}
}

func TestIPv6EncryptionScopeReady(t *testing.T) {
	withIPv6 := vpcCIDRs{
		primary: netip.MustParsePrefix("192.168.0.0/16"),
		ipv6:    []netip.Prefix{netip.MustParsePrefix("2600:1f14:abcd:ef00::/56")},
	}
	withoutIPv6 := vpcCIDRs{primary: netip.MustParsePrefix("192.168.0.0/16")}

	for _, tc := range []struct {
		name      string
		ipsec     bool
		conf      *option.DaemonConfig
		vpc       vpcCIDRs
		ready     bool
		expectErr bool
	}{
		{
			name:  "IPsec disabled",
			conf:  &option.DaemonConfig{EnableIPv6: true},
			vpc:   withoutIPv6,
			ready: true,
		},
		{
			name:  "IPv6 disabled",
			ipsec: true,
			conf:  &option.DaemonConfig{EnableIPv4: true},
			vpc:   withoutIPv6,
			ready: true,
		},
		{
			name:  "missing IPv6 scope",
			ipsec: true,
			conf:  &option.DaemonConfig{EnableIPv4: true, EnableIPv6: true},
			vpc:   withoutIPv6,
		},
		{
			name:  "discovered VPC IPv6 CIDRs",
			ipsec: true,
			conf:  &option.DaemonConfig{EnableIPv6: true},
			vpc:   withIPv6,
			ready: true,
		},
		{
			name:  "explicit IPv6 pod subnets",
			ipsec: true,
			conf: &option.DaemonConfig{
				EnableIPv6:     true,
				IPv6PodSubnets: []netip.Prefix{netip.MustParsePrefix("2001:db8::/48")},
			},
			vpc:   withoutIPv6,
			ready: true,
		},
		{
			name:  "configured IPv6 native routing CIDR",
			ipsec: true,
			conf: &option.DaemonConfig{
				EnableIPv6:            true,
				IPv6NativeRoutingCIDR: netip.MustParsePrefix("2001:db8::/48"),
			},
			vpc:   withoutIPv6,
			ready: true,
		},
		{
			name:  "configured IPv4 as IPv6 native routing CIDR",
			ipsec: true,
			conf: &option.DaemonConfig{
				EnableIPv6:            true,
				IPv6NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
			},
			vpc: withoutIPv6,
		},
		{
			name:  "explicit IPv6 pod subnets with an IPv4 entry",
			ipsec: true,
			conf: &option.DaemonConfig{
				EnableIPv6: true,
				IPv6PodSubnets: []netip.Prefix{
					netip.MustParsePrefix("2001:db8::/48"),
					netip.MustParsePrefix("10.0.0.0/8"),
				},
			},
			vpc:       withIPv6,
			expectErr: true,
		},
		{
			name:  "explicit IPv6 pod subnets with an IPv4-mapped entry",
			ipsec: true,
			conf: &option.DaemonConfig{
				EnableIPv6:     true,
				IPv6PodSubnets: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")},
			},
			vpc:       withIPv6,
			expectErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready, err := ipv6EncryptionScopeReady(tc.ipsec, tc.conf, tc.vpc)
			if tc.expectErr {
				require.Error(t, err)
				require.False(t, ready)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.ready, ready)
		})
	}

	t.Run("becomes ready once the operator populates the IPv6 CIDRs", func(t *testing.T) {
		conf := &option.DaemonConfig{EnableIPv6: true}
		node := &ciliumv2.CiliumNode{}
		node.Status.ENI.ENIs = map[string]awsTypes.ENI{
			"eni-1": {
				VPC: awsTypes.AwsVPC{
					ID:          "vpc-1",
					PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("192.168.0.0/16")),
				},
			},
		}
		ready, err := ipv6EncryptionScopeReady(true, conf, deriveVPCCIDRs(node))
		require.NoError(t, err)
		require.False(t, ready)

		eni := node.Status.ENI.ENIs["eni-1"]
		eni.VPC.IPv6CIDRs = prefixes("2600:1f14:abcd:ef00::/56")
		node.Status.ENI.ENIs["eni-1"] = eni
		ready, err = ipv6EncryptionScopeReady(true, conf, deriveVPCCIDRs(node))
		require.NoError(t, err)
		require.True(t, ready)
	})
}
