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
