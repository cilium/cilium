// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"testing"

	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	cilium "github.com/cilium/proxy/go/cilium/api"
)

func TestResourceEqual(t *testing.T) {
	policy := &cilium.NetworkPolicy{
		EndpointIps: []string{"10.0.0.1"},
		EndpointId:  1,
		EgressPerPortPolicies: []*cilium.PortNetworkPolicy{{
			Port: 80,
		}},
	}
	equalPolicy := proto.Clone(policy).(*cilium.NetworkPolicy)
	changedPolicy := proto.Clone(policy).(*cilium.NetworkPolicy)
	changedPolicy.EgressPerPortPolicies[0].Port = 443

	require.True(t, ResourceEqual(policy, policy))
	require.True(t, ResourceEqual(policy, equalPolicy))
	require.False(t, ResourceEqual(policy, changedPolicy))
	require.True(t, ResourceEqual((*cilium.NetworkPolicy)(nil), (*cilium.NetworkPolicy)(nil)))
	require.False(t, ResourceEqual((*cilium.NetworkPolicy)(nil), policy))

	listener := &envoy_config_listener.Listener{Name: "listener"}
	equalListener := proto.Clone(listener).(*envoy_config_listener.Listener)
	changedListener := proto.Clone(listener).(*envoy_config_listener.Listener)
	changedListener.Name = "changed"

	require.True(t, ResourceEqual(listener, equalListener))
	require.False(t, ResourceEqual(listener, changedListener))
	require.False(t, ResourceEqual(policy, listener))
}
