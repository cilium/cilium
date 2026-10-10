// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package typeurl

import (
	"testing"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	cilium "github.com/cilium/proxy/go/cilium/api"
)

func TestIndexRoundTrip(t *testing.T) {
	seen := NewSet()
	for index := range Indices() {
		url := index.URL()
		require.NotEmpty(t, url)
		roundTrip, ok := FromURL(url)
		require.True(t, ok)
		require.Equal(t, index, roundTrip)
		seen.Insert(index)
	}
	require.Equal(t, int(Count), seen.Len())

	index, ok := FromURL("type.googleapis.com/example.Unknown")
	require.False(t, ok)
	require.Equal(t, Count, index)
	require.Empty(t, Count.URL())
}

func TestFromMessage(t *testing.T) {
	tests := []struct {
		index    Index
		resource proto.Message
		typedNil proto.Message
	}{
		{Endpoint, &envoy_config_endpoint.ClusterLoadAssignment{}, (*envoy_config_endpoint.ClusterLoadAssignment)(nil)},
		{Cluster, &envoy_config_cluster.Cluster{}, (*envoy_config_cluster.Cluster)(nil)},
		{Route, &envoy_config_route.RouteConfiguration{}, (*envoy_config_route.RouteConfiguration)(nil)},
		{Listener, &envoy_config_listener.Listener{}, (*envoy_config_listener.Listener)(nil)},
		{Secret, &envoy_config_tls.Secret{}, (*envoy_config_tls.Secret)(nil)},
		{NetworkPolicy, &cilium.NetworkPolicy{}, (*cilium.NetworkPolicy)(nil)},
		{NetworkPolicyHosts, &cilium.NetworkPolicyHosts{}, (*cilium.NetworkPolicyHosts)(nil)},
	}
	for _, test := range tests {
		t.Run(test.index.URL(), func(t *testing.T) {
			for _, resource := range []proto.Message{test.resource, test.typedNil} {
				index, err := FromMessage(resource)
				require.NoError(t, err)
				require.Equal(t, test.index, index)
			}
		})
	}

	for _, resource := range []proto.Message{nil, &anypb.Any{}} {
		index, err := FromMessage(resource)
		require.Error(t, err)
		require.Equal(t, Count, index)
	}
}

func TestFixedMapTracksZeroValuesAndInitialization(t *testing.T) {
	var values Map[int]
	require.False(t, values.Known())
	require.True(t, values.Empty())

	values = NewMap[int]()
	require.True(t, values.Known())
	require.True(t, values.Empty())

	values.Set(Listener, 0)
	value, ok := values.Get(Listener)
	require.True(t, ok)
	require.Zero(t, value)
	require.Equal(t, 1, values.Len())

	values.Remove(Listener)
	require.True(t, values.Known())
	require.True(t, values.Empty())
}

func TestSetTracksMembershipAndInitialization(t *testing.T) {
	var zero Set
	removedFromZero := zero
	removedFromZero.Remove(Listener)
	removedLast := NewSet(Listener)
	removedLast.Remove(Listener)
	inserted := zero
	inserted.Insert(Listener)

	for _, test := range []struct {
		name  string
		set   Set
		known bool
		count int
	}{
		{"zero", zero, false, 0},
		{"remove from zero", removedFromZero, false, 0},
		{"union of zero sets", zero.Union(zero), false, 0},
		{"initialized empty", NewSet(), true, 0},
		{"remove last member", removedLast, true, 0},
		{"union with initialized empty", zero.Union(NewSet()), true, 0},
		{"insert into zero", inserted, true, 1},
		{"union with member", zero.Union(inserted), true, 1},
		{"all", All(), true, int(Count)},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.known, test.set.Known())
			require.Equal(t, test.count == 0, test.set.Empty())
			require.Equal(t, test.count, test.set.Len())
			if !test.set.Known() {
				require.Zero(t, test.set.bits)
			}
			count := 0
			for index := range test.set.Members() {
				require.True(t, test.set.Has(index))
				count++
			}
			require.Equal(t, test.count, count)
		})
	}
}
