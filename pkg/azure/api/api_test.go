// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/netip"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v9"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	// Required so SetID() resolves the Azure resource-ID parser.
	_ "github.com/cilium/cilium/pkg/azure/types/azureid"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestParseInterface(t *testing.T) {
	ifaceID := "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"
	subnetID := "/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet1"

	newIPConfig := func(ip string, primary bool) *armnetwork.InterfaceIPConfiguration {
		return &armnetwork.InterfaceIPConfiguration{
			Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress:  new(ip),
				Primary:           new(primary),
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				Subnet:            &armnetwork.Subnet{ID: new(subnetID)},
			},
		}
	}

	newIface := func(configs ...*armnetwork.InterfaceIPConfiguration) *armnetwork.Interface {
		return &armnetwork.Interface{
			ID: new(ifaceID),
			Properties: &armnetwork.InterfacePropertiesFormat{
				IPConfigurations: configs,
			},
		}
	}

	subnetMap := ipamTypes.SubnetMap{
		subnetID: &ipamTypes.Subnet{
			ID:   subnetID,
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		},
	}

	tests := []struct {
		name             string
		iface            *armnetwork.Interface
		subnets          ipamTypes.SubnetMap
		usePrimary       bool
		expectedIP       iputil.Addr
		expectedAddrs    []iputil.Addr
		expectedSubnetID string
		expectedCIDR     iputil.Prefix
		expectedGateway  iputil.Addr
	}{
		{
			name: "primary and secondaries, usePrimary=false",
			iface: newIface(
				newIPConfig("10.0.0.4", true),
				newIPConfig("10.0.0.5", false),
				newIPConfig("10.0.0.6", false),
			),
			subnets:    subnetMap,
			usePrimary: false,
			expectedIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
			expectedAddrs: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.6")),
			},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name: "primary and secondaries, usePrimary=true",
			iface: newIface(
				newIPConfig("10.0.0.4", true),
				newIPConfig("10.0.0.5", false),
				newIPConfig("10.0.0.6", false),
			),
			subnets:    subnetMap,
			usePrimary: true,
			expectedIP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
			expectedAddrs: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.6")),
			},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name:             "only primary, usePrimary=false, subnet derived from primary",
			iface:            newIface(newIPConfig("10.0.0.4", true)),
			subnets:          subnetMap,
			usePrimary:       false,
			expectedIP:       iputil.AddrFrom(netip.MustParseAddr("10.0.0.4")),
			expectedAddrs:    nil,
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name:          "no IPConfigurations",
			iface:         newIface(),
			usePrimary:    false,
			expectedIP:    iputil.Addr{},
			expectedAddrs: nil,
		},
		{
			name: "no primary flag set on any config",
			iface: newIface(
				newIPConfig("10.0.0.5", false),
				newIPConfig("10.0.0.6", false),
			),
			subnets:    subnetMap,
			usePrimary: false,
			expectedIP: iputil.Addr{},
			expectedAddrs: []iputil.Addr{
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.5")),
				iputil.AddrFrom(netip.MustParseAddr("10.0.0.6")),
			},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
		{
			name: "nil Primary pointer treated as non-primary",
			iface: newIface(&armnetwork.InterfaceIPConfiguration{
				Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
					PrivateIPAddress:  new("10.0.0.5"),
					Primary:           nil,
					ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
					Subnet:            &armnetwork.Subnet{ID: new(subnetID)},
				},
			}),
			subnets:          subnetMap,
			usePrimary:       false,
			expectedIP:       iputil.Addr{},
			expectedAddrs:    []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.5"))},
			expectedSubnetID: subnetID,
			expectedCIDR:     iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
			expectedGateway:  iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := parseInterface(hivetest.Logger(t), tt.iface, tt.subnets, tt.usePrimary)
			require.NotNil(t, got)
			require.Equal(t, tt.expectedIP, got.IP)
			require.Equal(t, tt.expectedSubnetID, got.Subnet.ID)
			require.Equal(t, tt.expectedCIDR, got.Subnet.CIDR)
			require.Equal(t, tt.expectedCIDR, got.CIDR) //nolint:staticcheck // verifies the deprecated mirror still tracks Subnet.CIDR
			require.Equal(t, tt.expectedGateway, got.Gateway)

			gotAddrs := make([]iputil.Addr, 0, len(got.Addresses))
			for _, a := range got.Addresses {
				gotAddrs = append(gotAddrs, a.IP)
				require.Equal(t, tt.expectedSubnetID, a.Subnet) //nolint:staticcheck // exercises the deprecated mirror
			}
			if tt.expectedAddrs == nil {
				require.Empty(t, gotAddrs)
			} else {
				require.Equal(t, tt.expectedAddrs, gotAddrs)
			}
		})
	}
}

func TestAvailableIPs(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	require.Equal(t, 16777216, availableIPs(cidr))
	cidr = netip.MustParsePrefix("1.1.1.1/32")
	require.Equal(t, 1, availableIPs(cidr))
}

func TestFindPublicIPPrefixByTags(t *testing.T) {
	prefixes := []*armnetwork.PublicIPPrefix{
		{
			ID: new("prefix1"),
			Tags: map[string]*string{
				"env":  new("prod"),
				"pool": new("pool-1"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          new("10.0.0.0/28"),
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: new("ip1")},
				},
			},
		},
		{
			ID: new("prefix2"),
			Tags: map[string]*string{
				"env": new("dev"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          new("10.1.0.0/28"),
			},
		},
		{
			// Not provisioned
			ID: new("prefix3"),
			Tags: map[string]*string{
				"env": new("staging"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateFailed),
				IPPrefix:          new("10.2.0.0/28"),
			},
		},
		{
			// Full
			ID: new("prefix4"),
			Tags: map[string]*string{
				"env": new("test"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: new(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          new("10.3.0.0/31"), // 2 IPs
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: new("ip1")},
					{ID: new("ip2")},
				},
			},
		},
	}

	// Test exact tag match
	prefixID, found := findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env":  "prod",
		"pool": "pool-1",
	})
	require.True(t, found)
	require.Equal(t, "prefix1", prefixID)

	// Test subset tag match
	prefixID, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "dev",
	})
	require.True(t, found)
	require.Equal(t, "prefix2", prefixID)

	// Test no match for non-existent tags
	_, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "nonexistent",
	})
	require.False(t, found)

	// Test skipping non-provisioned prefix
	_, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "staging",
	})
	require.False(t, found)

	// Test skipping full prefix
	_, found = findPublicIPPrefixByTags(prefixes, ipamTypes.Tags{
		"env": "test",
	})
	require.False(t, found)
}

func TestIsPublicIPProvisionFailed(t *testing.T) {
	tests := []struct {
		name                 string
		instanceViewStatuses []*armcompute.InstanceViewStatus
		expected             bool
	}{
		{
			name: "success",
			instanceViewStatuses: []*armcompute.InstanceViewStatus{
				{
					Code: new("ProvisioningState/succeeded"),
				},
			},
			expected: false,
		},
		{
			name: "failure",
			instanceViewStatuses: []*armcompute.InstanceViewStatus{
				{
					Code: new("ProvisioningState/failed/PublicIpPrefixOutOfIpAddressesForVMScaleSet"),
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, isPublicIPProvisionFailed(test.instanceViewStatuses))
		})
	}
}

func TestParseSubnetID(t *testing.T) {
	tests := []struct {
		name           string
		subnetID       string
		expectedRG     string
		expectedVNet   string
		expectedSubnet string
		expectError    bool
	}{
		{
			name:           "valid subnet ID",
			subnetID:       "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet",
			expectedRG:     "myResourceGroup",
			expectedVNet:   "myVNet",
			expectedSubnet: "mySubnet",
			expectError:    false,
		},
		{
			name:           "valid subnet ID with different names",
			subnetID:       "/subscriptions/87654321-4321-4321-4321-cba987654321/resourceGroups/test-rg-2/providers/Microsoft.Network/virtualNetworks/prod-vnet/subnets/app-subnet",
			expectedRG:     "test-rg-2",
			expectedVNet:   "prod-vnet",
			expectedSubnet: "app-subnet",
			expectError:    false,
		},
		{
			name:        "invalid format - missing subscription",
			subnetID:    "/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet",
			expectError: true,
		},
		{
			name:        "invalid format - missing resource group",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/providers/Microsoft.Network/virtualNetworks/myVNet/subnets/mySubnet",
			expectError: true,
		},
		{
			name:        "invalid format - missing virtual network",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/subnets/mySubnet",
			expectError: true,
		},
		{
			name:        "invalid format - missing subnet",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVNet",
			expectError: true,
		},
		{
			name:        "empty subnet ID",
			subnetID:    "",
			expectError: true,
		},
		{
			name:        "invalid provider namespace",
			subnetID:    "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Compute/virtualNetworks/myVNet/subnets/mySubnet",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rg, vnet, subnet, err := parseSubnetID(tt.subnetID)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if rg != tt.expectedRG {
				t.Errorf("expected resource group %q, got %q", tt.expectedRG, rg)
			}

			if vnet != tt.expectedVNet {
				t.Errorf("expected virtual network %q, got %q", tt.expectedVNet, vnet)
			}

			if subnet != tt.expectedSubnet {
				t.Errorf("expected subnet %q, got %q", tt.expectedSubnet, subnet)
			}
		})
	}
}
