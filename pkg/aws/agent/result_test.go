// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipmasq"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

func TestAllocationResult(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	node.Status.ENI.ENIs = map[string]awsTypes.ENI{
		"eni-1": {
			ID:  "eni-1",
			MAC: mac.MustParseMAC("aa:bb:cc:dd:ee:01"),
			Addresses: addrs(
				"10.1.1.10",
				"10.1.1.11",
			),
			Number: 1,
			Subnet: awsTypes.AwsSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24")),
			},
			VPC: awsTypes.AwsVPC{
				PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.0.0/16")),
				CIDRs:       prefixes("10.2.0.0/16"),
			},
		},
		"eni-2": {
			ID:  "eni-2",
			MAC: mac.MustParseMAC("aa:bb:cc:dd:ee:02"),
			Addresses: addrs(
				"10.3.1.20",
			),
			Number: 2,
			Subnet: awsTypes.AwsSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.3.1.0/24")),
			},
			VPC: awsTypes.AwsVPC{
				PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.0.0/16")),
				CIDRs:       prefixes("10.2.0.0/16"),
			},
		},
	}

	conf := &option.DaemonConfig{}
	logger := hivetest.Logger(t)

	t.Run("secondary IP on eni-1", func(t *testing.T) {
		result, err := allocationResult(logger, netip.MustParseAddr("10.1.1.10"), "", node.Status.ENI.ENIs, conf, nil)
		require.NoError(t, err)
		require.Equal(t, mac.MustParseMAC("aa:bb:cc:dd:ee:01"), result.PrimaryMAC)
		require.Equal(t, "1", result.InterfaceNumber)
		require.Equal(t, netip.MustParseAddr("10.1.1.1"), result.GatewayIP)
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.1.0.0/16"))
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.2.0.0/16"))
	})

	t.Run("secondary IP on eni-2", func(t *testing.T) {
		result, err := allocationResult(logger, netip.MustParseAddr("10.3.1.20"), "", node.Status.ENI.ENIs, conf, nil)
		require.NoError(t, err)
		require.Equal(t, mac.MustParseMAC("aa:bb:cc:dd:ee:02"), result.PrimaryMAC)
		require.Equal(t, "2", result.InterfaceNumber)
		require.Equal(t, netip.MustParseAddr("10.3.1.1"), result.GatewayIP)
	})

	t.Run("unknown IP returns error", func(t *testing.T) {
		_, err := allocationResult(logger, netip.MustParseAddr("10.99.99.99"), "", node.Status.ENI.ENIs, conf, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to find ENI for IP")
	})

	t.Run("native routing CIDR is appended", func(t *testing.T) {
		confWithNative := &option.DaemonConfig{
			EnableIPv4:            true,
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
		}
		result, err := allocationResult(logger, netip.MustParseAddr("10.1.1.10"), "", node.Status.ENI.ENIs, confWithNative, nil)
		require.NoError(t, err)
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.0.0.0/8"))
	})

	t.Run("IPv4 native routing CIDR is not appended when IPv4 is disabled", func(t *testing.T) {
		confWithNative := &option.DaemonConfig{
			IPv4NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
		}
		result, err := allocationResult(logger, netip.MustParseAddr("10.1.1.10"), "", node.Status.ENI.ENIs, confWithNative, nil)
		require.NoError(t, err)
		require.NotContains(t, result.CIDRs, netip.MustParsePrefix("10.0.0.0/8"))
	})
}

func TestAllocationResultPrefixDelegation(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	node.Status.ENI.ENIs = map[string]awsTypes.ENI{
		"eni-1": {
			ID:  "eni-1",
			MAC: mac.MustParseMAC("aa:bb:cc:dd:ee:01"),
			Prefixes: prefixes(
				"10.1.1.0/28",
				"10.1.1.16/28",
			),
			IPv6Prefixes: prefixes(
				"2001:db8::/80",
			),
			Number: 1,
			Subnet: awsTypes.AwsSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24")),
			},
			VPC: awsTypes.AwsVPC{
				PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.0.0/16")),
			},
		},
	}

	conf := &option.DaemonConfig{}
	logger := hivetest.Logger(t)

	t.Run("IP in first prefix", func(t *testing.T) {
		result, err := allocationResult(logger, netip.MustParseAddr("10.1.1.5"), "", node.Status.ENI.ENIs, conf, nil)
		require.NoError(t, err)
		require.Equal(t, mac.MustParseMAC("aa:bb:cc:dd:ee:01"), result.PrimaryMAC)
		require.Equal(t, "1", result.InterfaceNumber)
	})

	t.Run("IP in second prefix", func(t *testing.T) {
		result, err := allocationResult(logger, netip.MustParseAddr("10.1.1.20"), "", node.Status.ENI.ENIs, conf, nil)
		require.NoError(t, err)
		require.Equal(t, mac.MustParseMAC("aa:bb:cc:dd:ee:01"), result.PrimaryMAC)
	})

	t.Run("IP outside all prefixes", func(t *testing.T) {
		_, err := allocationResult(logger, netip.MustParseAddr("10.1.1.32"), "", node.Status.ENI.ENIs, conf, nil)
		require.Error(t, err)
	})

	t.Run("IP in IPv6 prefix", func(t *testing.T) {
		result, err := allocationResult(logger, netip.MustParseAddr("2001:db8::1"), "", node.Status.ENI.ENIs, conf, nil)
		require.NoError(t, err)
		require.Equal(t, mac.MustParseMAC("aa:bb:cc:dd:ee:01"), result.PrimaryMAC)
		require.Equal(t, "1", result.InterfaceNumber)
		require.Equal(t, netip.MustParseAddr("fe80:ec2::1"), result.GatewayIP)
	})

	t.Run("IPv6 native routing CIDR is appended", func(t *testing.T) {
		confWithNative := &option.DaemonConfig{
			EnableIPv6:            true,
			IPv6NativeRoutingCIDR: netip.MustParsePrefix("2001:db8::/64"),
		}
		result, err := allocationResult(logger, netip.MustParseAddr("2001:db8::1"), "", node.Status.ENI.ENIs, confWithNative, nil)
		require.NoError(t, err)
		require.Contains(t, result.CIDRs, netip.MustParsePrefix("2001:db8::/64"))
	})

	t.Run("IPv6 native routing CIDR is not appended when IPv6 is disabled", func(t *testing.T) {
		confWithNative := &option.DaemonConfig{
			IPv6NativeRoutingCIDR: netip.MustParsePrefix("2001:db8::/64"),
		}
		result, err := allocationResult(logger, netip.MustParseAddr("2001:db8::1"), "", node.Status.ENI.ENIs, confWithNative, nil)
		require.NoError(t, err)
		require.NotContains(t, result.CIDRs, netip.MustParsePrefix("2001:db8::/64"))
	})
}

func TestAllocationResultIPMasq(t *testing.T) {
	enis := map[string]awsTypes.ENI{
		"eni-1": {
			ID: "eni-1",
			Addresses: addrs(
				"10.1.1.226",
				"10.1.1.229",
			),
			Subnet: awsTypes.AwsSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.1.0/24")),
			},
			VPC: awsTypes.AwsVPC{
				ID:          "vpc-1",
				PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.1.0.0/16")),
				CIDRs: prefixes(
					"10.2.0.0/16",
				),
			},
		},
	}

	conf := &option.DaemonConfig{EnableIPMasqAgent: true}
	ipMasqAgent := ipmasq.NewIPMasqAgent(hivetest.Logger(t), "", ipMasqMapDummy{})
	require.NoError(t, ipMasqAgent.Start())
	defer ipMasqAgent.Stop()

	result, err := allocationResult(hivetest.Logger(t), netip.MustParseAddr("10.1.1.226"), "", enis, conf, ipMasqAgent)
	require.NoError(t, err)
	// The resulting CIDRs should contain the VPC CIDRs and the default
	// ip-masq-agent CIDRs from pkg/ipmasq/ipmasq.go
	require.ElementsMatch(
		t,
		[]netip.Prefix{
			// VPC CIDRs
			netip.MustParsePrefix("10.1.0.0/16"),
			netip.MustParsePrefix("10.2.0.0/16"),
			// Default ip-masq-agent CIDRs
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("192.0.0.0/24"),
			netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("192.88.99.0/24"),
			netip.MustParsePrefix("198.18.0.0/15"),
			netip.MustParsePrefix("198.51.100.0/24"),
			netip.MustParsePrefix("203.0.113.0/24"),
			netip.MustParsePrefix("240.0.0.0/4"),
			netip.MustParsePrefix("169.254.0.0/16"),
		},
		result.CIDRs,
	)
}

func TestAllocationResultIPMasqIPv6(t *testing.T) {
	enis := map[string]awsTypes.ENI{
		"eni-1": {
			ID:           "eni-1",
			IPv6Prefixes: prefixes("2001:db8::/80"),
			Subnet: awsTypes.AwsSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::/64")),
			},
		},
	}

	conf := &option.DaemonConfig{EnableIPv6: true, EnableIPMasqAgent: true}
	ipMasqAgent := ipmasq.NewIPMasqAgent(hivetest.Logger(t), "", ipMasqMapDummy{})
	require.NoError(t, ipMasqAgent.Start())
	defer ipMasqAgent.Stop()

	result, err := allocationResult(hivetest.Logger(t), netip.MustParseAddr("2001:db8::1"), "", enis, conf, ipMasqAgent)
	require.NoError(t, err)
	// Only the IPv6 ip-masq-agent CIDRs should be appended; the family
	// filter in allocationResult must exclude the IPv4 defaults.
	require.Contains(t, result.CIDRs, netip.MustParsePrefix("fe80::/10"))
	for _, c := range result.CIDRs {
		require.True(t, c.Addr().Is6(), "unexpected IPv4 CIDR %s for an IPv6 allocation", c)
	}
}

func TestEniContainsIP(t *testing.T) {
	eni := awsTypes.ENI{
		IP:           iputil.AddrFrom(netip.MustParseAddr("10.0.0.100")),
		Addresses:    addrs("10.0.0.1", "10.0.0.2"),
		Prefixes:     prefixes("10.0.1.0/28"),
		IPv6Prefixes: prefixes("2001:db8::/80"),
	}

	// Primary IP match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.100")))

	// Secondary address match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.1")))
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.2")))
	require.False(t, eniContainsIP(eni, netip.MustParseAddr("10.0.0.3")))

	// Prefix match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.1.0")))
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("10.0.1.15")))
	require.False(t, eniContainsIP(eni, netip.MustParseAddr("10.0.1.16")))

	// IPv6 prefix match
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("2001:db8::")))
	require.True(t, eniContainsIP(eni, netip.MustParseAddr("2001:db8::1")))
	require.False(t, eniContainsIP(eni, netip.MustParseAddr("2001:db8:0:0:1::")))

	// Empty ENI
	require.False(t, eniContainsIP(awsTypes.ENI{}, netip.MustParseAddr("10.0.0.1")))
}
