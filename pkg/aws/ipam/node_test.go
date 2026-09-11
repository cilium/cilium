// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	apiMock "github.com/cilium/cilium/pkg/aws/api/mock"
	metadataMock "github.com/cilium/cilium/pkg/aws/metadata/mock"
	"github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestGetMaximumAllocatableIPv4(t *testing.T) {
	api := apiMock.NewAPI(nil, nil, nil, nil)
	metadataMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMock)
	require.NoError(t, err)
	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
	}
	n.logger.Store(n.rootLogger)

	// With no k8sObj defined, it should return 0
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 0, we should be able to allocate up to 3x10-3 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(0))
	require.Equal(t, 27, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 1, we should be able to allocate up to 2x10-2 addresses
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(1))
	require.Equal(t, 18, n.GetMaximumAllocatableIPv4())

	// With instance-type = m5.large and first-interface-index = 4, we should return 0 as there is only 3 interfaces
	n.k8sObj = newCiliumNode("node", withInstanceType("m5.large"), withFirstInterfaceIndex(4))
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())

	// With instance-type = foo we should return 0
	n.k8sObj = newCiliumNode("node", withInstanceType("foo"))
	require.Equal(t, 0, n.GetMaximumAllocatableIPv4())
}

func Test_findSubnetInSameRouteTableWithNodeSubnet(t *testing.T) {
	routeTableMap := ipamTypes.RouteTableMap{
		"rt-1": &ipamTypes.RouteTable{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
				"subnet-3": {},
			},
		},
		"rt-2": &ipamTypes.RouteTable{
			ID:               "rt-2",
			VirtualNetworkID: "vpc-2",
			Subnets: map[string]struct{}{
				"subnet-4": {},
			},
		},
	}

	node := &Node{
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				ENI: types.ENISpec{
					VpcID:            "vpc-1",
					NodeSubnetID:     "subnet-1",
					AvailabilityZone: "us-east-1a",
				},
			},
		},
		manager: &InstancesManager{
			subnets: map[string]*ipamTypes.Subnet{
				"subnet-1": {
					ID:                 "subnet-1",
					AvailableAddresses: 10,
					AvailabilityZone:   "us-east-1a",
				},
				"subnet-2": {
					ID:                 "subnet-2",
					AvailableAddresses: 20,
					AvailabilityZone:   "us-east-1a",
				},
				"subnet-3": {
					ID:                 "subnet-3",
					AvailableAddresses: 25,
					AvailabilityZone:   "us-east-1b",
				},
				"subnet-4": {
					ID:                 "subnet-4",
					AvailableAddresses: 15,
					AvailabilityZone:   "us-east-1a",
				},
			},
			routeTables: routeTableMap,
		},
	}

	got := node.findSubnetInSameRouteTableWithNodeSubnet()
	require.NotNil(t, got)
	require.Equal(t, "subnet-2", got.ID)
	require.Equal(t, 20, got.AvailableAddresses)

	node.k8sObj.Spec.ENI.VpcID = "vpc-2"
	got = node.findSubnetInSameRouteTableWithNodeSubnet()
	require.Nil(t, got)

}

func Test_findSubnetInSameRouteTableWithNodeSubnet_UntrackedSubnets(t *testing.T) {
	// This test ensures that the function handles the case where the route table
	// references subnets that are not tracked by the manager because they were filtered
	// out by the subnetsFilters parameter
	routeTableMap := ipamTypes.RouteTableMap{
		"rt-1": &ipamTypes.RouteTable{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {}, // node subnet
				"subnet-2": {}, // tracked subnet
				"subnet-3": {}, // untracked subnet (not in manager.subnets)
				"subnet-4": {}, // another tracked subnet
			},
		},
	}

	node := &Node{
		k8sObj: &v2.CiliumNode{
			Spec: v2.NodeSpec{
				ENI: types.ENISpec{
					VpcID:            "vpc-1",
					NodeSubnetID:     "subnet-1",
					AvailabilityZone: "us-east-1a",
				},
			},
		},
		manager: &InstancesManager{
			subnets: map[string]*ipamTypes.Subnet{
				"subnet-1": {
					ID:                 "subnet-1",
					AvailableAddresses: 10,
					AvailabilityZone:   "us-east-1a",
				},
				"subnet-2": {
					ID:                 "subnet-2",
					AvailableAddresses: 20,
					AvailabilityZone:   "us-east-1a",
				},
				// subnet-3 is intentionally missing to simulate an untracked subnet
				"subnet-4": {
					ID:                 "subnet-4",
					AvailableAddresses: 30,
					AvailabilityZone:   "us-east-1a",
				},
			},
			routeTables: routeTableMap,
		},
	}

	// This should not panic and should return subnet-4 (highest available addresses)
	got := node.findSubnetInSameRouteTableWithNodeSubnet()
	require.NotNil(t, got)
	require.Equal(t, "subnet-4", got.ID)
	require.Equal(t, 30, got.AvailableAddresses)
}

func Test_checkSubnetInSameRouteTableWithNodeSubnet(t *testing.T) {
	routeTableMap := ipamTypes.RouteTableMap{
		"rt-1": &ipamTypes.RouteTable{
			ID:               "rt-1",
			VirtualNetworkID: "vpc-1",
			Subnets: map[string]struct{}{
				"subnet-1": {},
				"subnet-2": {},
			},
		},
		"rt-2": &ipamTypes.RouteTable{
			ID:               "rt-2",
			VirtualNetworkID: "vpc-2",
			Subnets: map[string]struct{}{
				"subnet-3": {},
			},
		},
	}

	tests := []struct {
		name     string
		nodeSpec *v2.CiliumNode
		subnet   *ipamTypes.Subnet
		want     bool
	}{
		{
			name: "same route table",
			nodeSpec: &v2.CiliumNode{
				Spec: v2.NodeSpec{
					ENI: types.ENISpec{
						VpcID:        "vpc-1",
						NodeSubnetID: "subnet-1",
					},
				},
			},
			subnet: &ipamTypes.Subnet{
				ID: "subnet-2",
			},
			want: true,
		},
		{
			name: "different route table",
			nodeSpec: &v2.CiliumNode{
				Spec: v2.NodeSpec{
					ENI: types.ENISpec{
						VpcID:        "vpc-1",
						NodeSubnetID: "subnet-1",
					},
				},
			},
			subnet: &ipamTypes.Subnet{
				ID: "subnet-3",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &Node{
				k8sObj: tt.nodeSpec,
				manager: &InstancesManager{
					routeTables: routeTableMap,
				},
			}
			got := node.checkSubnetInSameRouteTableWithNodeSubnet(tt.subnet)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsPrefixDelegated(t *testing.T) {
	tests := []struct {
		name            string
		instanceType    string
		expectDelegated bool
	}{
		{
			name:            "xen instance",
			instanceType:    "m4.large",
			expectDelegated: false,
		},
		{
			name:            "metal instance",
			instanceType:    "m5.metal",
			expectDelegated: true,
		},
		{
			name:            "nitro instance",
			instanceType:    "m5.large",
			expectDelegated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := apiMock.NewAPI(nil, nil, nil, nil)
			metadataMock, _ := metadataMock.NewMetadataMock()
			instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMock)
			require.NoError(t, err)
			n := &Node{
				rootLogger: hivetest.Logger(t),
				manager:    instances,
				k8sObj:     newCiliumNode("node1", withInstanceType(tt.instanceType)),
				node: &mockIPAMNode{
					prefixDelegation: true,
				},
			}
			n.logger.Store(n.rootLogger)

			require.Equal(t, tt.expectDelegated, n.IsPrefixDelegated())
		})
	}
}

func TestGetAttachedCIDRs(t *testing.T) {
	newNode := func(enis map[string]types.ENI) *Node {
		n := &Node{
			rootLogger: hivetest.Logger(t),
			enis:       enis,
			k8sObj:     &v2.CiliumNode{},
		}
		n.logger.Store(n.rootLogger)
		return n
	}

	t.Run("no ENIs returns empty set", func(t *testing.T) {
		n := newNode(nil)
		require.Empty(t, n.GetAttachedCIDRs())
	})

	t.Run("addresses and prefixes from multiple ENIs are merged", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))},
				Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28"))},
			},
			"eni-2": {
				Addresses:    []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("2001:db8::1"))},
				IPv6Prefixes: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1::/80"))},
			},
		})

		require.ElementsMatch(t, []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/32"),
			netip.MustParsePrefix("10.0.0.16/28"),
			netip.MustParsePrefix("2001:db8::1/128"),
			netip.MustParsePrefix("2001:db8:1::/80"),
		}, n.GetAttachedCIDRs())
	})

	t.Run("addresses expanded from a delegated prefix are not reported individually", func(t *testing.T) {
		// The EC2 layer expands every delegated prefix into eni.Addresses.
		// Only the prefix itself is attached as far as the release path is
		// concerned, since the agent records only the prefix in
		// Spec.IPAM.Pools.Allocated.
		addrs := []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.1.5"))}
		for i := range 16 {
			addrs = append(addrs, iputil.AddrFrom(netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", 16+i))))
		}

		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: addrs,
				Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28"))},
			},
		})

		require.ElementsMatch(t, []netip.Prefix{
			netip.MustParsePrefix("10.0.0.16/28"),
			netip.MustParsePrefix("10.0.1.5/32"),
		}, n.GetAttachedCIDRs())
	})

	t.Run("addresses covered by an IPv6 prefix are not reported individually", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{
					iputil.AddrFrom(netip.MustParseAddr("2001:db8:1::5")),
					iputil.AddrFrom(netip.MustParseAddr("2001:db8:2::1")),
				},
				IPv6Prefixes: []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("2001:db8:1::/80"))},
			},
		})

		require.ElementsMatch(t, []netip.Prefix{
			netip.MustParsePrefix("2001:db8:1::/80"),
			netip.MustParsePrefix("2001:db8:2::1/128"),
		}, n.GetAttachedCIDRs())
	})
}

func TestPrepareCIDRRelease(t *testing.T) {
	newNode := func(enis map[string]types.ENI) *Node {
		n := &Node{
			rootLogger: hivetest.Logger(t),
			enis:       enis,
			k8sObj:     &v2.CiliumNode{},
		}
		n.logger.Store(n.rootLogger)
		return n
	}

	t.Run("secondary IP mapped to correct ENI", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
				},
				Subnet: types.AwsSubnet{ID: "subnet-1"},
			},
			"eni-2": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.1.1"))},
				Subnet:    types.AwsSubnet{ID: "subnet-2"},
			},
		})

		actions := n.PrepareCIDRRelease([]netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")})

		require.Len(t, actions, 1)
		require.Equal(t, "eni-2", actions[0].InterfaceID)
		require.Equal(t, ipamTypes.PoolID("subnet-2"), actions[0].PoolID)
		require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.1.1/32")}, actions[0].CIDRsToRelease)
	})

	t.Run("prefix mapped to correct ENI", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))},
				Prefixes:  []iputil.Prefix{iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.16/28"))},
				Subnet:    types.AwsSubnet{ID: "subnet-1"},
			},
		})

		actions := n.PrepareCIDRRelease([]netip.Prefix{netip.MustParsePrefix("10.0.0.16/28")})

		require.Len(t, actions, 1)
		require.Equal(t, "eni-1", actions[0].InterfaceID)
		require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.16/28")}, actions[0].CIDRsToRelease)
	})

	t.Run("multiple CIDRs on same ENI grouped into one action", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.3")),
				},
				Subnet: types.AwsSubnet{ID: "subnet-1"},
			},
		})

		actions := n.PrepareCIDRRelease([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.3/32")})

		require.Len(t, actions, 1)
		require.Equal(t, "eni-1", actions[0].InterfaceID)
		require.ElementsMatch(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.3/32")}, actions[0].CIDRsToRelease)
	})

	t.Run("CIDRs on different ENIs produce separate actions", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))},
				Subnet:    types.AwsSubnet{ID: "subnet-1"},
			},
			"eni-2": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.1.1"))},
				Subnet:    types.AwsSubnet{ID: "subnet-2"},
			},
		})

		actions := n.PrepareCIDRRelease([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.1.1/32")})

		require.Len(t, actions, 2)
		eniIDs := map[string]bool{}
		for _, a := range actions {
			eniIDs[a.InterfaceID] = true
		}
		require.True(t, eniIDs["eni-1"])
		require.True(t, eniIDs["eni-2"])
	})

	t.Run("excluded ENIs are skipped", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))},
				Subnet:    types.AwsSubnet{ID: "subnet-1"},
				Tags:      map[string]string{"skip": "true"},
			},
		})
		n.k8sObj.Spec.ENI.ExcludeInterfaceTags = map[string]string{"skip": "true"}

		actions := n.PrepareCIDRRelease([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")})

		require.Empty(t, actions)
	})

	t.Run("CIDR not found on any ENI produces no action", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {
				Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))},
				Subnet:    types.AwsSubnet{ID: "subnet-1"},
			},
		})

		actions := n.PrepareCIDRRelease([]netip.Prefix{netip.MustParsePrefix("10.99.99.99/32")})

		require.Empty(t, actions)
	})

	t.Run("empty input returns empty result", func(t *testing.T) {
		n := newNode(map[string]types.ENI{
			"eni-1": {Addresses: []iputil.Addr{iputil.AddrFrom(netip.MustParseAddr("10.0.0.1"))}},
		})

		actions := n.PrepareCIDRRelease(nil)
		require.Empty(t, actions)
	})

	t.Run("primary IP is never released", func(t *testing.T) {
		// With UsePrimaryAddress=true, the primary IP is included in
		// eni.Addresses. The release path must still refuse to release
		// it because AWS rejects UnassignPrivateIpAddresses on a primary.
		n := newNode(map[string]types.ENI{
			"eni-1": {
				IP: iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
				Addresses: []iputil.Addr{
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.1")),
					iputil.AddrFrom(netip.MustParseAddr("10.0.0.2")),
				},
				Subnet: types.AwsSubnet{ID: "subnet-1"},
			},
		})

		actions := n.PrepareCIDRRelease(
			[]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("10.0.0.2/32")},
		)

		require.Len(t, actions, 1)
		require.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, actions[0].CIDRsToRelease)
	})
}

func TestENAQueueCountRequested(t *testing.T) {
	// Limits of an instance type supporting flexible ENA queues, here
	// c8i.8xlarge: 32 vCPUs, a budget of 128 queues and at most 32 queues per
	// interface.
	flexible := ipamTypes.Limits{
		Adapters:                         10,
		VCpus:                            32,
		SupportsFlexibleENAQueues:        true,
		MaxENAQueueCount:                 128,
		MaxENAQueueCountPerInterface:     32,
		DefaultENAQueueCountPerInterface: 8,
	}
	// Limits of an instance type which does not let the queue count be chosen.
	fixed := ipamTypes.Limits{Adapters: 3, VCpus: 2}

	tests := []struct {
		name      string
		spec      string
		limits    ipamTypes.Limits
		expected  int32
		isManaged bool
	}{
		{
			name:      "unset leaves the queue count to AWS",
			spec:      "",
			limits:    flexible,
			expected:  0,
			isManaged: false,
		},
		{
			// The value the agent writes when nothing is configured, and the
			// way to opt a node out where a broader configuration applies.
			name:      "default leaves the queue count to AWS",
			spec:      "default",
			limits:    flexible,
			expected:  0,
			isManaged: false,
		},
		{
			name:      "ignored on an instance type without flexible queues",
			spec:      "auto",
			limits:    fixed,
			expected:  0,
			isManaged: false,
		},
		{
			name:      "auto uses the maximum per interface when below the vCPU count",
			spec:      "auto",
			limits:    flexible,
			expected:  32,
			isManaged: true,
		},
		{
			// AWS rejects an attachment whose queue count is not a power of
			// two, and vCPU counts of 12, 24, 48, 72, 96, 192 and 384 exist.
			// Rounding up rather than down keeps one queue per CPU: a driver
			// creates no more queues than there are CPUs, so asking for 16 on
			// a 12 vCPU instance yields 12 queues, where asking for 8 would
			// leave four CPUs without one.
			name: "auto rounds the vCPU count up to a power of two",
			spec: "auto",
			limits: ipamTypes.Limits{
				VCpus:                        12,
				SupportsFlexibleENAQueues:    true,
				MaxENAQueueCount:             48,
				MaxENAQueueCountPerInterface: 16,
			},
			expected:  16,
			isManaged: true,
		},
		{
			// Rounding up never exceeds what the instance type allows per
			// interface, which AWS would reject.
			name: "auto rounding up is capped by the maximum per interface",
			spec: "auto",
			limits: ipamTypes.Limits{
				VCpus:                        64,
				SupportsFlexibleENAQueues:    true,
				MaxENAQueueCount:             120,
				MaxENAQueueCountPerInterface: 32,
			},
			expected:  32,
			isManaged: true,
		},
		{
			name:      "an explicit count is rounded down to a power of two",
			spec:      "12",
			limits:    flexible,
			expected:  8,
			isManaged: true,
		},
		{
			name: "auto is capped by the number of vCPUs",
			spec: "auto",
			limits: ipamTypes.Limits{
				VCpus:                        8,
				SupportsFlexibleENAQueues:    true,
				MaxENAQueueCount:             128,
				MaxENAQueueCountPerInterface: 32,
			},
			expected:  8,
			isManaged: true,
		},
		{
			name: "auto ignores an unknown vCPU count",
			spec: "auto",
			limits: ipamTypes.Limits{
				SupportsFlexibleENAQueues:    true,
				MaxENAQueueCount:             128,
				MaxENAQueueCountPerInterface: 32,
			},
			expected:  32,
			isManaged: true,
		},
		{
			name:      "an explicit count is used as is",
			spec:      "16",
			limits:    flexible,
			expected:  16,
			isManaged: true,
		},
		{
			name:      "an explicit count is capped by the maximum per interface",
			spec:      "64",
			limits:    flexible,
			expected:  32,
			isManaged: true,
		},
		{
			name: "an explicit count above the vCPU count is kept",
			spec: "32",
			limits: ipamTypes.Limits{
				VCpus:                        8,
				SupportsFlexibleENAQueues:    true,
				MaxENAQueueCount:             128,
				MaxENAQueueCountPerInterface: 32,
			},
			expected:  32,
			isManaged: true,
		},
		{
			name:      "an unparsable count leaves the queue count to AWS",
			spec:      "many",
			limits:    flexible,
			expected:  0,
			isManaged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, managed := enaQueueCountRequested(tt.spec, tt.limits)
			require.Equal(t, tt.expected, count)
			require.Equal(t, tt.isManaged, managed)
		})
	}
}

func TestENAQueueBudget(t *testing.T) {
	limits := ipamTypes.Limits{
		MaxENAQueueCount:                 128,
		MaxENAQueueCountPerInterface:     32,
		DefaultENAQueueCountPerInterface: 8,
	}

	tests := []struct {
		name              string
		enis              map[string]types.ENI
		expectedUsed      int
		expectedRemaining int
	}{
		{
			name:              "no interface consumes no queue",
			enis:              map[string]types.ENI{},
			expectedUsed:      0,
			expectedRemaining: 128,
		},
		{
			name: "the queues of every attached interface are counted",
			enis: map[string]types.ENI{
				"eni-0": {ID: "eni-0", Number: 0, ENAQueueCount: 8},
				"eni-1": {ID: "eni-1", Number: 1, ENAQueueCount: 32},
			},
			expectedUsed:      40,
			expectedRemaining: 88,
		},
		{
			name: "an exhausted budget leaves no queue",
			enis: map[string]types.ENI{
				"eni-0": {ID: "eni-0", Number: 0, ENAQueueCount: 32},
				"eni-1": {ID: "eni-1", Number: 1, ENAQueueCount: 32},
				"eni-2": {ID: "eni-2", Number: 2, ENAQueueCount: 32},
				"eni-3": {ID: "eni-3", Number: 3, ENAQueueCount: 32},
			},
			expectedUsed:      128,
			expectedRemaining: 0,
		},
		{
			name: "a budget consumed beyond its size does not go negative",
			enis: map[string]types.ENI{
				"eni-0": {ID: "eni-0", Number: 0, ENAQueueCount: 128},
				"eni-1": {ID: "eni-1", Number: 1, ENAQueueCount: 32},
			},
			expectedUsed:      160,
			expectedRemaining: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Node{enis: tt.enis}
			used, remaining := n.enaQueueBudgetLocked(limits)
			require.Equal(t, tt.expectedUsed, used)
			require.Equal(t, tt.expectedRemaining, remaining)
		})
	}
}

// TestResyncNormalizesENAQueueCounts asserts that n.enis holds the number of
// queues every ENI runs with, including the interfaces the EC2 API reports no
// count for, so that the queue budget accounting reads the count rather than
// deriving it.
func TestResyncNormalizesENAQueueCounts(t *testing.T) {
	api := apiMock.NewAPI(nil, nil, nil, nil)
	metadataMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMock)
	require.NoError(t, err)

	const instanceID = "i-000"
	// eni-requested was attached with a queue count and the EC2 API reports it.
	// eni-default was not, so it runs with the 8 queues c8i.8xlarge assigns by
	// default and the EC2 API reports no count for it.
	instances.instances.Update(instanceID, &types.ENI{ID: "eni-requested", Number: 1, ENAQueueCount: 32})
	instances.instances.Update(instanceID, &types.ENI{ID: "eni-default", Number: 0})

	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		node:       &mockIPAMNode{instanceID: instanceID},
		k8sObj: newCiliumNode("node",
			withInstanceType("c8i.8xlarge"),
			withFirstInterfaceIndex(0),
		),
	}
	n.logger.Store(n.rootLogger)

	_, _, err = n.ResyncInterfacesAndIPs(t.Context(), hivetest.Logger(t))
	require.NoError(t, err)

	require.Equal(t, int32(32), n.enis["eni-requested"].ENAQueueCount)
	require.Equal(t, int32(8), n.enis["eni-default"].ENAQueueCount)

	limits, ok := n.getLimits()
	require.True(t, ok)
	used, remaining := n.enaQueueBudgetLocked(limits)
	require.Equal(t, 40, used)
	require.Equal(t, 88, remaining)
}

// enaQueueTestNode returns a node of an instance type supporting flexible ENA
// queues, with the given ENIs already attached.
func enaQueueTestNode(t *testing.T, spec string, enis map[string]types.ENI) *Node {
	api := apiMock.NewAPI(nil, nil, nil, nil)
	metadataMock, _ := metadataMock.NewMetadataMock()
	instances, err := NewInstancesManager(t.Context(), hivetest.Logger(t), api, metadataMock)
	require.NoError(t, err)

	n := &Node{
		rootLogger: hivetest.Logger(t),
		manager:    instances,
		enis:       enis,
		k8sObj: newCiliumNode("node",
			withInstanceType("c8i.8xlarge"),
			withFirstInterfaceIndex(0),
			withENAQueueCount(spec),
		),
	}
	n.logger.Store(n.rootLogger)

	return n
}

// attachedENIs returns count ENIs consuming queues queues each.
func attachedENIs(count int, queues int32) map[string]types.ENI {
	enis := map[string]types.ENI{}
	for i := range count {
		id := fmt.Sprintf("eni-%d", i)
		enis[id] = types.ENI{ID: id, Number: i, ENAQueueCount: queues}
	}
	return enis
}

func TestPrepareIPAllocationENAQueueBudget(t *testing.T) {
	// c8i.8xlarge allows 10 interfaces and 128 ENA queues in total.
	tests := []struct {
		name               string
		spec               string
		enis               map[string]types.ENI
		expectedEmptySlots int
	}{
		{
			name:               "queue count unset leaves the interface slots alone",
			spec:               "",
			enis:               attachedENIs(4, 32),
			expectedEmptySlots: 6,
		},
		{
			name:               "queue count default leaves the interface slots alone",
			spec:               "default",
			enis:               attachedENIs(4, 32),
			expectedEmptySlots: 6,
		},
		{
			name:               "interface slots are offered while the budget lasts",
			spec:               "auto",
			enis:               attachedENIs(1, 8),
			expectedEmptySlots: 9,
		},
		{
			name:               "no interface slot is offered once the budget is exhausted",
			spec:               "auto",
			enis:               attachedENIs(4, 32),
			expectedEmptySlots: 0,
		},
		{
			name:               "an explicit queue count exhausts the budget just as well",
			spec:               "16",
			enis:               attachedENIs(8, 16),
			expectedEmptySlots: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := enaQueueTestNode(t, tt.spec, tt.enis)

			a, err := n.PrepareIPAllocation(hivetest.Logger(t))
			require.NoError(t, err)
			require.Equal(t, tt.expectedEmptySlots, a.EmptyInterfaceSlots)
		})
	}
}

func TestGrantENAQueueCount(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		enis        map[string]types.ENI
		expected    int32
		expectedErr bool
	}{
		{
			name:     "no queue count is requested when the setting is unset",
			spec:     "",
			enis:     attachedENIs(1, 8),
			expected: 0,
		},
		{
			name:     "the full count is granted when the budget allows it",
			spec:     "auto",
			enis:     attachedENIs(1, 8),
			expected: 32,
		},
		{
			name:     "the count is reduced to what is left of the budget",
			spec:     "auto",
			enis:     attachedENIs(3, 32),
			expected: 32,
		},
		{
			// 8 queues are left, which is already a power of two.
			name:     "the count is reduced below what was requested",
			spec:     "32",
			enis:     attachedENIs(5, 24),
			expected: 8, // 128 - 5*24 queues left
		},
		{
			name:        "an exhausted budget fails before the interface is attached",
			spec:        "auto",
			enis:        attachedENIs(4, 32),
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := enaQueueTestNode(t, tt.spec, tt.enis)
			limits, ok := n.getLimits()
			require.True(t, ok)

			count, err := n.grantENAQueueCount(tt.spec, limits, hivetest.Logger(t))
			if tt.expectedErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, count)
		})
	}
}

func TestEffectiveENAQueueCount(t *testing.T) {
	tests := []struct {
		name         string
		eni          types.ENI
		defaultCount int32
		expected     int32
	}{
		{
			name:         "a reported count is what the interface runs with",
			eni:          types.ENI{ID: "eni-1", Number: 1, ENAQueueCount: 32},
			defaultCount: 8,
			expected:     32,
		},
		{
			// The EC2 API reports no count for the primary interface, as it was
			// not attached with a requested queue count.
			name:         "an interface without a reported count runs with the default",
			eni:          types.ENI{ID: "eni-0", Number: 0},
			defaultCount: 8,
			expected:     8,
		},
		{
			// Before the first resync determined the default of the instance
			// type, no count can be reported for such an interface.
			name:     "an unknown default reports no count",
			eni:      types.ENI{ID: "eni-0", Number: 0},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, effectiveENAQueueCount(&tt.eni, tt.defaultCount))
		})
	}
}

func TestFloorPowerOfTwo(t *testing.T) {
	// The vCPU counts of AWS instance types which are not powers of two.
	require.Equal(t, 8, floorPowerOfTwo(12))
	require.Equal(t, 16, floorPowerOfTwo(24))
	require.Equal(t, 32, floorPowerOfTwo(48))
	require.Equal(t, 64, floorPowerOfTwo(72))
	require.Equal(t, 64, floorPowerOfTwo(96))
	require.Equal(t, 128, floorPowerOfTwo(192))
	require.Equal(t, 256, floorPowerOfTwo(384))

	// Powers of two are returned unchanged.
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64, 128} {
		require.Equal(t, n, floorPowerOfTwo(n))
	}

	require.Equal(t, 0, floorPowerOfTwo(0))
	require.Equal(t, 0, floorPowerOfTwo(-1))
}

func TestCeilPowerOfTwo(t *testing.T) {
	// The vCPU counts of AWS instance types which are not powers of two.
	require.Equal(t, 16, ceilPowerOfTwo(12))
	require.Equal(t, 32, ceilPowerOfTwo(24))
	require.Equal(t, 64, ceilPowerOfTwo(48))
	require.Equal(t, 128, ceilPowerOfTwo(72))
	require.Equal(t, 128, ceilPowerOfTwo(96))
	require.Equal(t, 256, ceilPowerOfTwo(192))
	require.Equal(t, 512, ceilPowerOfTwo(384))

	// Powers of two are returned unchanged.
	for _, n := range []int{1, 2, 4, 8, 16, 32, 64, 128} {
		require.Equal(t, n, ceilPowerOfTwo(n))
	}

	require.Equal(t, 0, ceilPowerOfTwo(0))
	require.Equal(t, 0, ceilPowerOfTwo(-1))
}

func TestGrantENAQueueCountRoundsBudgetDown(t *testing.T) {
	// c8i.8xlarge: a budget of 128 queues, at most 32 per interface. Three
	// interfaces at 32 and one at 8 leave 24 queues, which is not a power of
	// two, so the grant has to round down to 16 rather than ask for 24 and be
	// rejected by AWS.
	enis := attachedENIs(3, 32)
	enis["eni-primary"] = types.ENI{ID: "eni-primary", Number: 9, ENAQueueCount: 8}

	n := enaQueueTestNode(t, "auto", enis)
	limits, ok := n.getLimits()
	require.True(t, ok)

	used, remaining := n.enaQueueBudgetLocked(limits)
	require.Equal(t, 104, used)
	require.Equal(t, 24, remaining)

	count, err := n.grantENAQueueCount("auto", limits, hivetest.Logger(t))
	require.NoError(t, err)
	require.Equal(t, int32(16), count)
}
