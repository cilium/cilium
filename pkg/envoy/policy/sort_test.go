// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoypolicy

import (
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/require"
)

var PortNetworkPolicyRule1 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: nil,
	L7:             nil,
}

var PortNetworkPolicyRule2 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint32{1},
	L7:             nil,
}

var PortNetworkPolicyRule3 = &cilium.PortNetworkPolicyRule{
	RemotePolicies: []uint32{1, 2},
	L7:             nil,
}

// TODO: Test sorting Kafka rules.

func TestSortPortNetworkPolicyRules(t *testing.T) {
	rulesMap := map[string]*cilium.PortNetworkPolicyRule{
		"3": PortNetworkPolicyRule3,
		"2": PortNetworkPolicyRule2,
		"1": PortNetworkPolicyRule1,
	}
	expected := []*cilium.PortNetworkPolicyRule{
		PortNetworkPolicyRule1,
		PortNetworkPolicyRule2,
		PortNetworkPolicyRule3,
	}
	result := SortPortNetworkPolicyRulesMap(rulesMap)
	require.Equal(t, expected, result)
	require.Nil(t, SortPortNetworkPolicyRulesMap(nil))
}

var PortNetworkPolicy1 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_TCP,
	Port:     10001,
}

var PortNetworkPolicy2 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10001,
}

var PortNetworkPolicy3 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10002,
}

var PortNetworkPolicy4 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10002,
	EndPort:  10003,
}

var PortNetworkPolicy5 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10002,
	EndPort:  10004,
}

var PortNetworkPolicy6 = &cilium.PortNetworkPolicy{
	Protocol: envoy_config_core.SocketAddress_UDP,
	Port:     10003,
	EndPort:  10004,
}

func TestSortPortNetworkPolicies(t *testing.T) {
	var slice, expected []*cilium.PortNetworkPolicy

	slice = []*cilium.PortNetworkPolicy{
		PortNetworkPolicy6,
		PortNetworkPolicy5,
		PortNetworkPolicy4,
		PortNetworkPolicy3,
		PortNetworkPolicy2,
		PortNetworkPolicy1,
	}
	expected = []*cilium.PortNetworkPolicy{
		PortNetworkPolicy1,
		PortNetworkPolicy2,
		PortNetworkPolicy3,
		PortNetworkPolicy4,
		PortNetworkPolicy5,
		PortNetworkPolicy6,
	}
	SortPortNetworkPolicies(slice)
	require.Equal(t, expected, slice)
}
