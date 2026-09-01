// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

type ipMasqMapDummy struct{}

func (ipMasqMapDummy) Update(netip.Prefix) error     { return nil }
func (ipMasqMapDummy) Delete(netip.Prefix) error     { return nil }
func (ipMasqMapDummy) Dump() ([]netip.Prefix, error) { return nil, nil }

func TestAllocationResult(t *testing.T) {
	interfaces := []azureTypes.AzureInterface{
		{
			ID:      "azure-interface-1",
			MAC:     mac.MustParseMAC("00:00:5e:00:53:01"),
			Gateway: iputil.AddrFrom(netip.MustParseAddr("10.10.1.1")),
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.10.1.0/24")),
			},
			Addresses: []azureTypes.AzureAddress{
				{IP: iputil.AddrFrom(netip.MustParseAddr("10.10.1.5")), State: azureTypes.StateSucceeded},
			},
		},
		{
			ID:      "azure-interface-2",
			MAC:     mac.MustParseMAC("00:00:5e:00:53:02"),
			Gateway: iputil.AddrFrom(netip.MustParseAddr("10.20.1.1")),
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.20.1.0/24")),
			},
			Addresses: []azureTypes.AzureAddress{
				{IP: iputil.AddrFrom(netip.MustParseAddr("10.20.1.5")), State: azureTypes.StateSucceeded},
				{IP: iputil.AddrFrom(netip.MustParseAddr("10.20.1.6")), State: "updating"},
			},
		},
	}

	conf := &option.DaemonConfig{
		EnableIPv4:            true,
		EnableIPMasqAgent:     true,
		IPv4NativeRoutingCIDR: netip.MustParsePrefix("10.0.0.0/8"),
	}
	configPath := filepath.Join(t.TempDir(), "ip-masq-agent.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(`nonMasqueradeCIDRs:
- 172.16.0.0/12
- 2001:db8:ffff::/48
`), 0o600))
	ipMasqAgent := ipmasq.NewIPMasqAgent(hivetest.Logger(t), configPath, ipMasqMapDummy{})
	require.NoError(t, ipMasqAgent.Start())
	defer ipMasqAgent.Stop()

	pool := ipam.Pool("default")
	result, err := allocationResult(
		netip.MustParseAddr("10.20.1.5"),
		pool,
		interfaces,
		conf,
		ipMasqAgent,
	)
	require.NoError(t, err)
	require.Equal(t, netip.MustParseAddr("10.20.1.5"), result.IP)
	require.Equal(t, pool, result.IPPoolName)
	require.Equal(t, mac.MustParseMAC("00:00:5e:00:53:02"), result.PrimaryMAC)
	require.Equal(t, netip.MustParseAddr("10.20.1.1"), result.GatewayIP)
	require.Equal(t, "0", result.InterfaceNumber)
	require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.20.1.0/24"))
	require.Contains(t, result.CIDRs, netip.MustParsePrefix("10.0.0.0/8"))
	require.Contains(t, result.CIDRs, netip.MustParsePrefix("172.16.0.0/12"))
	require.NotContains(t, result.CIDRs, netip.MustParsePrefix("2001:db8:ffff::/48"))

	_, err = allocationResult(
		netip.MustParseAddr("10.20.1.6"),
		pool,
		interfaces,
		conf,
		ipMasqAgent,
	)
	require.ErrorContains(t, err, "unable to find Azure interface for IP 10.20.1.6")

	_, err = allocationResult(
		netip.MustParseAddr("10.30.1.5"),
		pool,
		interfaces,
		conf,
		ipMasqAgent,
	)
	require.ErrorContains(t, err, "unable to find Azure interface for IP 10.30.1.5")
}
