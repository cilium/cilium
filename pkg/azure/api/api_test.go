// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/netip"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v7"
	"github.com/stretchr/testify/require"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

func TestAvailableIPs(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	require.Equal(t, 16777216, availableIPs(cidr))
	cidr = netip.MustParsePrefix("1.1.1.1/32")
	require.Equal(t, 1, availableIPs(cidr))
}

func TestFindPublicIPPrefixByTags(t *testing.T) {
	prefixes := []*armnetwork.PublicIPPrefix{
		{
			ID: to.Ptr("prefix1"),
			Tags: map[string]*string{
				"env":  to.Ptr("prod"),
				"pool": to.Ptr("pool-1"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          to.Ptr("10.0.0.0/28"),
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: to.Ptr("ip1")},
				},
			},
		},
		{
			ID: to.Ptr("prefix2"),
			Tags: map[string]*string{
				"env": to.Ptr("dev"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          to.Ptr("10.1.0.0/28"),
			},
		},
		{
			// Not provisioned
			ID: to.Ptr("prefix3"),
			Tags: map[string]*string{
				"env": to.Ptr("staging"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateFailed),
				IPPrefix:          to.Ptr("10.2.0.0/28"),
			},
		},
		{
			// Full
			ID: to.Ptr("prefix4"),
			Tags: map[string]*string{
				"env": to.Ptr("test"),
			},
			Properties: &armnetwork.PublicIPPrefixPropertiesFormat{
				ProvisioningState: to.Ptr(armnetwork.ProvisioningStateSucceeded),
				IPPrefix:          to.Ptr("10.3.0.0/31"), // 2 IPs
				PublicIPAddresses: []*armnetwork.ReferencedPublicIPAddress{
					{ID: to.Ptr("ip1")},
					{ID: to.Ptr("ip2")},
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
					Code: to.Ptr("ProvisioningState/succeeded"),
				},
			},
			expected: false,
		},
		{
			name: "failure",
			instanceViewStatuses: []*armcompute.InstanceViewStatus{
				{
					Code: to.Ptr("ProvisioningState/failed/PublicIpPrefixOutOfIpAddressesForVMScaleSet"),
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
