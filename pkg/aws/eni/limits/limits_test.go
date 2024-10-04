// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/cilium/cilium/operator/option"
	ec2mock "github.com/cilium/cilium/pkg/aws/ec2/mock"
)

func TestGet(t *testing.T) {
	option.Config.AWSInstanceLimitMapping = map[string]string{"a2.custom2": "4,5,6"}

	_, ok := Get("unknown")
	require.False(t, ok)

	l, ok := Get("m3.large")
	require.True(t, ok)
	require.NotEqual(t, 0, l.Adapters)
	require.NotEqual(t, 0, l.IPv4)
	require.Equal(t, "xen", l.HypervisorType)

	UpdateFromUserDefinedMappings(option.Config.AWSInstanceLimitMapping)
	l, ok = Get("a2.custom2")
	require.True(t, ok)
	require.Equal(t, 4, l.Adapters)
	require.Equal(t, 5, l.IPv4)
	require.Equal(t, 6, l.IPv6)
}

func TestUpdateFromUserDefinedMappings(t *testing.T) {
	m1 := map[string]string{"a1.medium": "2,4,100"}

	err := UpdateFromUserDefinedMappings(m1)
	require.NoError(t, err)

	limit, ok := Get("a1.medium")
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

func TestUpdateFromEC2API(t *testing.T) {
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
	api := ec2mock.NewAPI(nil, nil, nil)
	api.UpdateInstanceTypes(instanceTypes)
	UpdateFromEC2API(context.Background(), api)

	limit, ok := Get("newinstance.medium")
	require.True(t, ok)
	require.Equal(t, 8, limit.Adapters)
	require.Equal(t, 30, limit.IPv4)
	require.Equal(t, 30, limit.IPv6)
}
