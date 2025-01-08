// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/cilium/cilium/operator/option"
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

func init() {
	api = ec2mock.NewAPI(nil, nil, nil)
	InitEC2APIUpdateTrigger(api, testTriggerMinInterval, testEC2apiTimeout, testEC2apiRetryCount)
}

func TestGet(t *testing.T) {
	option.Config.AWSInstanceLimitMapping = map[string]string{"a2.custom2": "4,5,6"}

	// Test 1: Get unknown instance type (should trigger EC2 API call but fail)
	// sleep to wait for the trigger can be triggered
	time.Sleep(testTriggerMinInterval)
	limit, ok := Get("unknown", api)
	require.False(t, ok)
	require.Equal(t, ipamTypes.Limits{}, limit)

	// Test 2: Get predefined instance type
	UpdateFromUserDefinedMappings(option.Config.AWSInstanceLimitMapping)
	limit, ok = Get("a2.custom2", api)
	require.True(t, ok)
	require.Equal(t, ipamTypes.Limits{Adapters: 4, IPv4: 5, IPv6: 6}, limit)

	// Test 4: Get instance type from EC2 API
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "newtype",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  ptr.To[int32](4),
			Ipv4AddressesPerInterface: ptr.To[int32](15),
			Ipv6AddressesPerInterface: ptr.To[int32](15),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
	}})
	// sleep to wait for the trigger can be triggered
	time.Sleep(testTriggerMinInterval)
	limit, ok = Get("newtype", api)
	require.True(t, ok)
	require.Equal(t, ipamTypes.Limits{
		Adapters:       4,
		IPv4:           15,
		IPv6:           15,
		HypervisorType: "nitro",
	}, limit)
}

func TestUpdateFromUserDefinedMappings(t *testing.T) {
	api := ec2mock.NewAPI(nil, nil, nil)
	m1 := map[string]string{"a1.medium": "2,4,100"}

	err := UpdateFromUserDefinedMappings(m1)
	require.NoError(t, err)

	limit, ok := Get("a1.medium", api)
	require.True(t, ok)
	require.Equal(t, 2, limit.Adapters)
	require.Equal(t, 4, limit.IPv4)
	require.Equal(t, 100, limit.IPv6)
}

func TestParseLimitString(t *testing.T) {
	limitString1 := "4,5 ,6"
	limitString2 := "4,5,a"
	limitString3 := "4,5"
	limitString4 := "45"
	limitString5 := ","
	limitString6 := ""

	limit, err := parseLimitString(limitString1)
	require.NoError(t, err)
	require.Equal(t, 4, limit.Adapters)
	require.Equal(t, 5, limit.IPv4)
	require.Equal(t, 6, limit.IPv6)

	limit, err = parseLimitString(limitString2)
	require.Error(t, err)

	limit, err = parseLimitString(limitString3)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid limit value")
	require.NotEqual(t, 4, limit.Adapters)
	require.NotEqual(t, 5, limit.IPv4)
	require.Equal(t, 0, limit.IPv6)

	limit, err = parseLimitString(limitString4)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid limit value")

	limit, err = parseLimitString(limitString5)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid limit value")

	limit, err = parseLimitString(limitString6)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid limit value")
}

func TestInitEC2APIUpdateTrigger(t *testing.T) {
	instanceTypes := []ec2_types.InstanceTypeInfo{
		{
			Hypervisor:   ec2_types.InstanceTypeHypervisorXen,
			InstanceType: ec2_types.InstanceType("newinstance.medium"),
			NetworkInfo: &ec2_types.NetworkInfo{
				Ipv4AddressesPerInterface: ptr.To[int32](30),
				Ipv6AddressesPerInterface: ptr.To[int32](30),
				MaximumNetworkInterfaces:  ptr.To[int32](8),
			},
		},
	}
	api.UpdateInstanceTypes(instanceTypes)
	// sleep to wait for the trigger can be triggered
	time.Sleep(testTriggerMinInterval)
	limit, ok := Get("newinstance.medium", api)
	require.True(t, ok)
	require.Equal(t, 8, limit.Adapters)
	require.Equal(t, 30, limit.IPv4)
	require.Equal(t, 30, limit.IPv6)
}
