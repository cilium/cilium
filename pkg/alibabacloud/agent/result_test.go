// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/mac"
)

func TestResolveRoutingMetadata(t *testing.T) {
	logger := hivetest.Logger(t)
	addr := netip.MustParseAddr("10.20.1.5")
	eni := alibabaCloudTypes.ENI{
		Type:          alibabaCloudTypes.ENITypeSecondary,
		MACAddress:    mac.MustParseMAC("00:00:5e:00:53:02"),
		Tags:          alibabaCloudTypes.FillTagWithENIIndex(map[string]string{}, 3),
		VSwitch:       alibabaCloudTypes.VSwitch{CIDRBlock: iputil.PrefixFrom(netip.MustParsePrefix("10.20.1.0/24"))},
		PrivateIPSets: []alibabaCloudTypes.PrivateIPSet{{PrivateIpAddress: iputil.AddrFrom(addr), Primary: true}},
	}
	cn := &ciliumv2.CiliumNode{}
	cn.Status.AlibabaCloud.ENIs = map[string]alibabaCloudTypes.ENI{"eni-1": eni}
	r := &resolver{logger: logger}
	pool := ipam.Pool("default")
	result, err := r.ResolveRoutingMetadata(cn, addr, pool)
	require.NoError(t, err)
	require.Equal(t, &ipam.AllocationResult{
		IP: addr, IPPoolName: pool, PrimaryMAC: eni.MACAddress,
		GatewayIP: netip.MustParseAddr("10.20.1.253"), InterfaceNumber: "3",
	}, result)

	_, err = r.ResolveRoutingMetadata(cn, netip.MustParseAddr("10.20.1.6"), pool)
	require.ErrorContains(t, err, "unable to find AlibabaCloud ENI")
	_, err = r.ResolveRoutingMetadata(nil, addr, pool)
	require.Error(t, err)

	eni.VSwitch.CIDRBlock = iputil.Prefix{}
	eni.Tags = nil
	cn.Status.AlibabaCloud.ENIs["eni-1"] = eni
	result, err = r.ResolveRoutingMetadata(cn, addr, pool)
	require.NoError(t, err)
	require.False(t, result.GatewayIP.IsValid())
	require.Equal(t, "0", result.InterfaceNumber)

	eni.Type = alibabaCloudTypes.ENITypePrimary
	cn.Status.AlibabaCloud.ENIs["eni-1"] = eni
	_, err = r.ResolveRoutingMetadata(cn, addr, pool)
	require.Error(t, err, "the host interface must not provide Pod addresses")
}

func TestResolveRoutingMetadataIPv6(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cidr      string
		prefix    string
		gateway   string
		wantError bool
	}{
		{
			name: "global gateway",
			cidr: "2001:db8:1:2::/64", prefix: "2001:db8:1:2:3::/80",
			gateway: "2001:db8:1:2:ffff:ffff:ffff:fffd",
		},
		{
			name: "unique local gateway",
			cidr: "fd00:0:0:1::/64", prefix: "fd00:0:0:1:23::/80",
			gateway: "fd00:0:0:1:ffff:ffff:ffff:fffd",
		},
		{name: "missing IPv6 CIDR", prefix: "2001:db8:1:2:3::/80", wantError: true},
		{name: "wrong address family", cidr: "10.0.0.0/24", prefix: "2001:db8:1:2:3::/80", wantError: true},
		{name: "IPv4-mapped IPv6 CIDR", cidr: "::ffff:10.0.0.0/120", prefix: "2001:db8:1:2:3::/80", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			eniMAC := mac.MustParseMAC("00:00:5e:00:53:02")
			prefix := netip.MustParsePrefix(tt.prefix)
			eni := alibabaCloudTypes.ENI{
				Type:       alibabaCloudTypes.ENITypeSecondary,
				MACAddress: eniMAC,
				Tags:       alibabaCloudTypes.FillTagWithENIIndex(map[string]string{}, 3),
				VSwitch: alibabaCloudTypes.VSwitch{
					VSwitchID: "vsw-1",
					CIDRBlock: iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
				},
				IPv6Prefixes: []iputil.Prefix{iputil.PrefixFrom(prefix)},
			}
			if tt.cidr != "" {
				eni.VSwitch.IPv6CIDRBlock = iputil.PrefixFrom(netip.MustParsePrefix(tt.cidr))
			}
			cn := &ciliumv2.CiliumNode{}
			cn.Status.AlibabaCloud.ENIs = map[string]alibabaCloudTypes.ENI{"eni-1": eni}
			r := &resolver{logger: hivetest.Logger(t)}
			for _, addr := range []netip.Addr{prefix.Addr().Next(), prefix.Addr().Next().Next()} {
				result, err := r.ResolveRoutingMetadata(cn, addr, "default")
				if tt.wantError {
					require.ErrorContains(t, err, "invalid IPv6 CIDR for AlibabaCloud vSwitch vsw-1")
					require.Nil(t, result)
					continue
				}
				require.NoError(t, err)
				require.Equal(t, &ipam.AllocationResult{
					IP: addr, IPPoolName: "default", PrimaryMAC: eniMAC,
					GatewayIP: netip.MustParseAddr(tt.gateway), InterfaceNumber: "3",
				}, result)
				require.False(t, prefix.Contains(result.GatewayIP), "derive the gateway from the vSwitch CIDR, not the ENI prefix")
			}
			_, err := r.ResolveRoutingMetadata(cn, netip.MustParseAddr("2001:db8:ffff::1"), "default")
			require.ErrorContains(t, err, "unable to find AlibabaCloud ENI")
			eni.Type = alibabaCloudTypes.ENITypePrimary
			cn.Status.AlibabaCloud.ENIs["eni-1"] = eni
			_, err = r.ResolveRoutingMetadata(cn, prefix.Addr().Next(), "default")
			require.ErrorContains(t, err, "unable to find AlibabaCloud ENI")
		})
	}
}
