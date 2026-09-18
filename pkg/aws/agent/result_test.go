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
