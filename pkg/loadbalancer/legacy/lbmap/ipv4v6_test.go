// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestLbAlgAndSessionAffinityTimeout(t *testing.T) {
	var (
		alg1        loadbalancer.SVCLoadBalancingAlgorithm = 1
		alg2        loadbalancer.SVCLoadBalancingAlgorithm = 2
		time1       uint32                                 = 8
		time2       uint32                                 = 16
		invalidTime uint32                                 = 1 << 24
	)
	type testCase struct {
		desc string
		svc  ServiceValue
	}
	testCases := []testCase{
		{"v4", &Service4Value{}},
		{"v6", &Service6Value{}},
	}
	type testScenario struct {
		desc   string
		action func(*testing.T, ServiceValue)
	}
	testScenarios := []testScenario{
		{
			"GetLbAlg",
			func(t *testing.T, svc ServiceValue) {
				svc.SetLbAlg(alg1) // This is to verify that earlier writes are not visible if overridden later.
				svc.SetLbAlg(alg2)
				svc.SetSessionAffinityTimeoutSec(time1) // This is to verify that writing to different bits of the same 32-bit variable does not affect the LbAlg bits.
				require.Equal(t, alg2, svc.GetLbAlg())
			},
		},
		{
			"GetSessionAffinityTimeoutSec",
			func(t *testing.T, svc ServiceValue) {
				svc.SetSessionAffinityTimeoutSec(time1) // This is to verify that earlier writes are not visible if overridden later.
				svc.SetSessionAffinityTimeoutSec(time2)
				svc.SetLbAlg(alg2) // This is to verify that writing to different bits of the same 32-bit variable does not affect the SessionAffinityTimeoutSec bits.
				require.Equal(t, time2, svc.GetSessionAffinityTimeoutSec())
			},
		},
		{
			"Too large SessionAffinityTimeoutSec",
			func(t *testing.T, svc ServiceValue) {
				require.Error(t, svc.SetSessionAffinityTimeoutSec(invalidTime))
			},
		},
	}
	for _, tc := range testCases {
		for _, ts := range testScenarios {
			t.Run(tc.desc+"/"+ts.desc, func(t *testing.T) {
				svc := tc.svc.New().(ServiceValue)
				ts.action(t, svc)
			})
		}

	}
}

func TestL7LBProxyPort(t *testing.T) {
	var (
		port1 uint16 = 123
		port2 uint16 = 456
	)
	type testCase struct {
		desc string
		svc  ServiceValue
	}
	testCases := []testCase{
		{"v4", &Service4Value{}},
		{"v6", &Service6Value{}},
	}
	type testScenario struct {
		desc   string
		action func(*testing.T, ServiceValue)
	}
	testScenarios := []testScenario{
		{
			"GetL7LBProxyPort",
			func(t *testing.T, svc ServiceValue) {
				svc.SetL7LBProxyPort(port1) // This is to verify that earlier writes are not visible if overridden later.
				svc.SetL7LBProxyPort(port2)
				require.Equal(t, port2, svc.GetL7LBProxyPort())
			},
		},
		{
			"Ignore algorithm and affinity timeout",
			func(t *testing.T, svc ServiceValue) {
				svc.SetLbAlg(loadbalancer.SVCLoadBalancingAlgorithmMaglev)
				svc.SetSessionAffinityTimeoutSec(10) // These are to verify that usages of other cases of the union are overwritten when L7 Proxy port is set.
				svc.SetL7LBProxyPort(port1)
				require.Equal(t, port1, svc.GetL7LBProxyPort())
			},
		},
	}
	for _, tc := range testCases {
		for _, ts := range testScenarios {
			t.Run(tc.desc+"/"+ts.desc, func(t *testing.T) {
				svc := tc.svc.New().(ServiceValue)
				ts.action(t, svc)
			})
		}

	}
}
