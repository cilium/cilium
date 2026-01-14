// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apimock "github.com/cilium/cilium/pkg/azure/api/mock"
	"github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
)

var (
	subnets = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             netip.MustParsePrefix("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
	}

	subnets2 = []*ipamTypes.Subnet{
		{
			ID:               "subnet-1",
			CIDR:             netip.MustParsePrefix("1.1.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-2",
			CIDR:             netip.MustParsePrefix("2.2.0.0/16"),
			VirtualNetworkID: "vpc-2",
			Tags: map[string]string{
				"tag1": "tag1",
			},
		},
		{
			ID:               "subnet-3",
			CIDR:             netip.MustParsePrefix("3.3.0.0/16"),
			VirtualNetworkID: "vpc-1",
			Tags: map[string]string{
				"tag2": "tag2",
			},
		},
	}

	vnets = []*ipamTypes.VirtualNetwork{
		{ID: "vpc-0"},
		{ID: "vpc-1"},
	}
)

func iteration1(t *testing.T, api *apimock.API, mngr *InstancesManager) {
	instances := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-1")
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	resource = &types.AzureInterface{
		SecurityGroup: "sg3",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.3.3",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-3")
	instances.Update("i-2", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	api.UpdateInstances(instances)
	mngr.Resync(t.Context())
}

func iteration2(t *testing.T, api *apimock.API, mngr *InstancesManager) {
	api.UpdateSubnets(subnets2)

	instances := ipamTypes.NewInstanceMap()

	resource := &types.AzureInterface{
		SecurityGroup: "sg1",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.1.1",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-1")
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	resource = &types.AzureInterface{
		SecurityGroup: "sg2",
		Addresses: []types.AzureAddress{
			{
				IP:     "3.3.3.3",
				Subnet: "subnet-3",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-2")
	instances.Update("i-1", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	resource = &types.AzureInterface{
		SecurityGroup: "sg3",
		Addresses: []types.AzureAddress{
			{
				IP:     "1.1.3.3",
				Subnet: "subnet-1",
				State:  types.StateSucceeded,
			},
		},
		State: types.StateSucceeded,
	}
	resource.SetID("intf-3")
	instances.Update("i-2", ipamTypes.InterfaceRevision{
		Resource: resource.DeepCopy(),
	})

	api.UpdateInstances(instances)
	mngr.Resync(t.Context())
}

func TestSubnetDiscovery(t *testing.T) {
	api := apimock.NewAPI(subnets, vnets)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api)
	require.NotNil(t, mngr)

	require.Nil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"])
	require.Nil(t, mngr.subnets["subnet-3"])

	iteration1(t, api, mngr)

	// Only subnets referenced by actual instances should be discovered
	// iteration1 creates instances using only subnet-1, not subnet-2 or subnet-3
	require.NotNil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"]) // Should NOT be discovered (no instances use it)
	require.Nil(t, mngr.subnets["subnet-3"]) // Should NOT be discovered (no instances use it)

	iteration2(t, api, mngr)

	// iteration2 uses subnet-1 and subnet-3, but still NOT subnet-2
	require.NotNil(t, mngr.subnets["subnet-1"])
	require.Nil(t, mngr.subnets["subnet-2"]) // Still should NOT be discovered (no instances use it)
	require.NotNil(t, mngr.subnets["subnet-3"])
}

func TestExtractSubnetIDs(t *testing.T) {
	api := apimock.NewAPI(subnets, vnets)
	require.NotNil(t, api)

	mngr := NewInstancesManager(hivetest.Logger(t), api)
	require.NotNil(t, mngr)

	// Create 100 instances across only 2 different subnets to test deduplication
	instances := ipamTypes.NewInstanceMap()

	for i := 0; i < 100; i++ {
		instanceID := fmt.Sprintf("vm-%d", i)
		interfaceID := fmt.Sprintf("/subscriptions/xxx/resourceGroups/g1/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/%s/networkInterfaces/eth0", instanceID)

		// Alternate between subnet-1 and subnet-3 (50 instances each)
		var subnetID string
		if i%2 == 0 {
			subnetID = "subnet-1"
		} else {
			subnetID = "subnet-3"
		}

		resource := &types.AzureInterface{
			Name:          "eth0",
			SecurityGroup: "sg1",
			Addresses: []types.AzureAddress{
				{
					IP:     fmt.Sprintf("10.0.%d.%d", (i%254)+1, (i%254)+10),
					Subnet: subnetID,
					State:  types.StateSucceeded,
				},
			},
		}
		resource.SetID(interfaceID)

		instances.Update(instanceID, ipamTypes.InterfaceRevision{
			Resource: resource.DeepCopy(),
		})
	}

	// Extract subnet IDs and verify deduplication
	subnetIDs := mngr.extractSubnetIDs(instances)

	// Should return exactly 2 unique subnet IDs despite 100 instances
	require.Len(t, subnetIDs, 2, "Expected exactly 2 unique subnet IDs from 100 instances")

	// Verify the correct subnet IDs are present
	subnetSet := make(map[string]bool)
	for _, subnetID := range subnetIDs {
		subnetSet[subnetID] = true
	}

	require.True(t, subnetSet["subnet-1"], "Should contain subnet-1")
	require.True(t, subnetSet["subnet-3"], "Should contain subnet-3")
	require.False(t, subnetSet["subnet-2"], "Should NOT contain subnet-2 (no instances use it)")
}
