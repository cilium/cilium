// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cilium/hive/hivetest"

	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	testTriggerMinInterval = time.Second
	testEC2apiTimeout      = time.Second
	testEC2apiRetryCount   = 2
)

var api *ec2mock.API

func TestGet(t *testing.T) {
	api = ec2mock.NewAPI(nil, nil, nil, nil)
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "test.large",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  ptr.To[int32](4),
			Ipv4AddressesPerInterface: ptr.To[int32](5),
			Ipv6AddressesPerInterface: ptr.To[int32](6),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
	}})
	newLimitsGetter, err := NewLimitsGetter(hivetest.Logger(t), api, testTriggerMinInterval, testEC2apiTimeout, testEC2apiRetryCount)
	require.NoError(t, err)

	// Test 1: Get unknown instance type
	limit, ok := newLimitsGetter.Get("unknown")
	require.False(t, ok)
	require.Equal(t, ipamTypes.Limits{}, limit)
	// Test 2: Get Known instance type
	limit, ok = newLimitsGetter.Get("test.large")
	require.True(t, ok)
	require.Equal(t, ipamTypes.Limits{
		Adapters:       4,
		IPv4:           5,
		IPv6:           6,
		HypervisorType: "nitro",
	}, limit)

	// Test 3: EC2 API call and update limits but trigger can't be triggered
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "newtype",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  ptr.To[int32](4),
			Ipv4AddressesPerInterface: ptr.To[int32](15),
			Ipv6AddressesPerInterface: ptr.To[int32](15),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
	}})

	limit, ok = newLimitsGetter.Get("newtype")
	require.False(t, ok)
	require.Equal(t, ipamTypes.Limits{}, limit)
	// Test 4: EC2 API call and update limits and trigger can be triggered after triggerMinInterval
	require.Eventually(t, func() bool {
		limit, ok = newLimitsGetter.Get("newtype")
		return ok && limit == ipamTypes.Limits{
			Adapters:       4,
			IPv4:           15,
			IPv6:           15,
			HypervisorType: "nitro",
		}
	}, 2*testTriggerMinInterval, time.Millisecond)
}

func TestInitEC2APIUpdateTrigger(t *testing.T) {
	// Setup mock API with some test instance types
	api := ec2mock.NewAPI(nil, nil, nil, nil)
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{
		{
			InstanceType: "test.large",
			NetworkInfo: &ec2_types.NetworkInfo{
				MaximumNetworkInterfaces:  ptr.To[int32](4),
				Ipv4AddressesPerInterface: ptr.To[int32](10),
				Ipv6AddressesPerInterface: ptr.To[int32](10),
			},
			Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
		},
	})

	// Create a new LimitsGetter instance
	limitsGetter, err := NewLimitsGetter(hivetest.Logger(t), api, testTriggerMinInterval, testEC2apiTimeout, testEC2apiRetryCount)
	require.NotNil(t, limitsGetter)
	require.NoError(t, err)

	// Verify the fields are set correctly
	require.Equal(t, testTriggerMinInterval, limitsGetter.triggerMinInterval)
	require.Equal(t, testEC2apiTimeout, limitsGetter.ec2APITimeout)
	require.Equal(t, testEC2apiRetryCount, limitsGetter.ec2APIRetryCount)
	require.NotNil(t, limitsGetter.limitsUpdateTrigger)

	// Verify that the limits were actually retrieved
	limits, ok := limitsGetter.Get("test.large")
	require.True(t, ok)
	require.Equal(t, ipamTypes.Limits{
		Adapters:       4,
		IPv4:           10,
		IPv6:           10,
		HypervisorType: "nitro",
	}, limits)
}
