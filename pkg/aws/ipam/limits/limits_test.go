// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"testing"

	"github.com/stretchr/testify/require"

	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/aws/api/mock"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	testTriggerMinInterval = time.Second
	testEC2apiTimeout      = time.Second
	testEC2apiRetryCount   = 2
)

var api *mock.API

func TestGet(t *testing.T) {
	api = mock.NewAPI(nil, nil, nil, nil)
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "test.large",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  new(int32(4)),
			Ipv4AddressesPerInterface: new(int32(5)),
			Ipv6AddressesPerInterface: new(int32(6)),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
		BareMetal:  new(false),
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
		IsBareMetal:    false,
	}, limit)

	// Test 3: EC2 API call and update limits but trigger can't be triggered
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{{
		InstanceType: "newtype",
		NetworkInfo: &ec2_types.NetworkInfo{
			MaximumNetworkInterfaces:  new(int32(4)),
			Ipv4AddressesPerInterface: new(int32(15)),
			Ipv6AddressesPerInterface: new(int32(15)),
		},
		Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
		BareMetal:  new(false),
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
			IsBareMetal:    false,
		}
	}, 2*testTriggerMinInterval, time.Millisecond)
}

func TestInitEC2APIUpdateTrigger(t *testing.T) {
	// Setup mock API with some test instance types
	api := mock.NewAPI(nil, nil, nil, nil)
	api.UpdateInstanceTypes([]ec2_types.InstanceTypeInfo{
		{
			InstanceType: "test.large",
			NetworkInfo: &ec2_types.NetworkInfo{
				MaximumNetworkInterfaces:  new(int32(4)),
				Ipv4AddressesPerInterface: new(int32(10)),
				Ipv6AddressesPerInterface: new(int32(10)),
			},
			Hypervisor: ec2_types.InstanceTypeHypervisorNitro,
			BareMetal:  new(false),
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
		IsBareMetal:    false,
	}, limits)
}

func TestENAQueueLimits(t *testing.T) {
	// The ENA queue limits of an instance type are reported per network card,
	// and Cilium attaches ENIs to network card 0.
	card := func(index, maxTotal, maxPerInterface, defaultPerInterface int32) ec2_types.NetworkCardInfo {
		return ec2_types.NetworkCardInfo{
			NetworkCardIndex:                 new(index),
			MaximumEnaQueueCount:             new(maxTotal),
			MaximumEnaQueueCountPerInterface: new(maxPerInterface),
			DefaultEnaQueueCountPerInterface: new(defaultPerInterface),
		}
	}

	tests := []struct {
		name        string
		networkInfo *ec2_types.NetworkInfo
		expected    enaQueueLimit
	}{
		{
			name:        "no network info",
			networkInfo: nil,
			expected:    enaQueueLimit{},
		},
		{
			// The default is reported for every instance type, so it is read
			// even when the queue count cannot be chosen: it is the number of
			// queues the interfaces of the instance run with.
			name: "instance type without flexible queue support",
			networkInfo: &ec2_types.NetworkInfo{
				NetworkCards: []ec2_types.NetworkCardInfo{card(0, 128, 32, 8)},
			},
			expected: enaQueueLimit{
				supported:           false,
				maxTotal:            128,
				maxPerInterface:     32,
				defaultPerInterface: 8,
			},
		},
		{
			name: "limits are read from the network card Cilium attaches to",
			networkInfo: &ec2_types.NetworkInfo{
				FlexibleEnaQueuesSupport: ec2_types.FlexibleEnaQueuesSupportSupported,
				NetworkCards: []ec2_types.NetworkCardInfo{
					card(1, 256, 64, 16),
					card(0, 128, 32, 8),
				},
			},
			expected: enaQueueLimit{
				supported:           true,
				maxTotal:            128,
				maxPerInterface:     32,
				defaultPerInterface: 8,
			},
		},
		{
			name: "partial limits do not allow choosing a queue count",
			networkInfo: &ec2_types.NetworkInfo{
				FlexibleEnaQueuesSupport: ec2_types.FlexibleEnaQueuesSupportSupported,
				NetworkCards: []ec2_types.NetworkCardInfo{
					{NetworkCardIndex: new(int32(0)), DefaultEnaQueueCountPerInterface: new(int32(8))},
				},
			},
			expected: enaQueueLimit{supported: false, defaultPerInterface: 8},
		},
		{
			name: "no limits reported for network card 0",
			networkInfo: &ec2_types.NetworkInfo{
				FlexibleEnaQueuesSupport: ec2_types.FlexibleEnaQueuesSupportSupported,
				NetworkCards:             []ec2_types.NetworkCardInfo{card(1, 256, 64, 16)},
			},
			expected: enaQueueLimit{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, enaQueueLimits(tt.networkInfo))
		})
	}
}
