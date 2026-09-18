// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"testing"

	"github.com/stretchr/testify/require"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// seedResource sets up desired state for snapshot-generation tests without
// applying a mutation or marking a resource name as changed.
func (state *nodeState) seedResource(typeURL typeurl.Index, name string, resource cache_types.Resource) {
	resources := state.resources[typeURL]
	if resources == nil {
		resources = make(map[string]resourceEntry)
		state.resources[typeURL] = resources
	}
	resources[name] = resourceEntry{resource: resource}
}

func TestNodeStateUsesSemanticEqualityAndTracksChangedNames(t *testing.T) {
	current := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": {Name: "listener"}},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"route": {Name: "route"}},
		Clusters:  map[string]*envoy_config_cluster.Cluster{"cluster": {Name: "cluster"}},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"endpoint": {ClusterName: "endpoint"}},
		Secrets:   map[string]*envoy_config_tls.Secret{"secret": {Name: "secret"}},
	}

	equal := xds.Resources{
		Listeners: make(map[string]*envoy_config_listener.Listener),
		Routes:    make(map[string]*envoy_config_route.RouteConfiguration),
		Clusters:  make(map[string]*envoy_config_cluster.Cluster),
		Endpoints: make(map[string]*envoy_config_endpoint.ClusterLoadAssignment),
		Secrets:   make(map[string]*envoy_config_tls.Secret),
	}
	equal.Listeners["listener"] = proto.Clone(current.Listeners["listener"]).(*envoy_config_listener.Listener)
	equal.Routes["route"] = proto.Clone(current.Routes["route"]).(*envoy_config_route.RouteConfiguration)
	equal.Clusters["cluster"] = proto.Clone(current.Clusters["cluster"]).(*envoy_config_cluster.Cluster)
	equal.Endpoints["endpoint"] = proto.Clone(current.Endpoints["endpoint"]).(*envoy_config_endpoint.ClusterLoadAssignment)
	equal.Secrets["secret"] = proto.Clone(current.Secrets["secret"]).(*envoy_config_tls.Secret)

	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", current.Listeners["listener"])
	state.seedResource(typeurl.Route, "route", current.Routes["route"])
	state.seedResource(typeurl.Cluster, "cluster", current.Clusters["cluster"])
	state.seedResource(typeurl.Endpoint, "endpoint", current.Endpoints["endpoint"])
	state.seedResource(typeurl.Secret, "secret", current.Secrets["secret"])
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(ResourceMutations{Upserted: equal}, 1)
	require.True(t, changedTypeURLs.Empty())
	require.True(t, inverse.empty())
	require.True(t, changes.empty())
	for _, resource := range []struct {
		typeURL typeurl.Index
		value   cache_types.Resource
		name    string
	}{
		{typeurl.Listener, current.Listeners["listener"], "listener"},
		{typeurl.Route, current.Routes["route"], "route"},
		{typeurl.Cluster, current.Clusters["cluster"], "cluster"},
		{typeurl.Endpoint, current.Endpoints["endpoint"], "endpoint"},
		{typeurl.Secret, current.Secrets["secret"], "secret"},
	} {
		actual := state.getResource(resource.typeURL, resource.name)
		require.NotNil(t, actual)
		require.Same(t, resource.value, actual)
	}

	removed := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": current.Listeners["listener"]},
		Clusters:  map[string]*envoy_config_cluster.Cluster{"cluster": current.Clusters["cluster"]},
	}
	upserted := xds.Resources{Secrets: map[string]*envoy_config_tls.Secret{
		"new-secret": {Name: "new-secret"},
	}}

	changes, changedTypeURLs, inverse = state.prepareResourceMutation(ResourceMutations{Removed: removed, Upserted: upserted}, 1)
	require.Len(t, changes.more, 2, "three changed resources should share one overflow slice")
	state.commitResourceMutation(changes, 1)
	require.Equal(t, typeurl.NewSet(
		typeurl.Listener,
		typeurl.Cluster,
		typeurl.Secret,
	), changedTypeURLs)
	require.Equal(t, 1, state.typeStates[typeurl.Listener].changedResourceNames.Len())
	require.True(t, state.typeStates[typeurl.Listener].changedResourceNames.Has("listener"))
	require.Equal(t, 1, state.typeStates[typeurl.Cluster].changedResourceNames.Len())
	require.True(t, state.typeStates[typeurl.Cluster].changedResourceNames.Has("cluster"))
	require.Equal(t, 1, state.typeStates[typeurl.Secret].changedResourceNames.Len())
	require.True(t, state.typeStates[typeurl.Secret].changedResourceNames.Has("new-secret"))
	require.Empty(t, state.typeStates[typeurl.Route].changedResourceNames)
	require.Empty(t, state.typeStates[typeurl.Endpoint].changedResourceNames)
	require.Empty(t, state.typeStates[typeurl.NetworkPolicyHosts].changedResourceNames)
	inverseListener, _ := inverse.get(typeurl.Listener, "listener")
	inverseCluster, _ := inverse.get(typeurl.Cluster, "cluster")
	inverseSecret, _ := inverse.get(typeurl.Secret, "new-secret")
	require.Equal(t, current.Listeners["listener"], inverseListener.resource)
	require.Equal(t, current.Clusters["cluster"], inverseCluster.resource)
	require.Nil(t, inverseSecret.resource)
	require.Nil(t, state.getResource(typeurl.Listener, "listener"))
	require.Nil(t, state.getResource(typeurl.Cluster, "cluster"))
	require.NotNil(t, state.getResource(typeurl.Secret, "secret"))
	require.NotNil(t, state.getResource(typeurl.Secret, "new-secret"))

	// The previously published generation remains immutable.
	require.Contains(t, current.Listeners, "listener")
	require.Contains(t, current.Clusters, "cluster")
	require.NotContains(t, current.Secrets, "new-secret")
}

func (state *nodeState) seedResourceAtGeneration(typeURL typeurl.Index, name string, resource cache_types.Resource, generation callbacks.Generation) {
	state.seedResource(typeURL, name, resource)
	entry := state.resources[typeURL][name]
	entry.revision = generation.Revision()
	entry.transaction = generation.TransactionID()
	state.resources[typeURL][name] = entry
	state.typeStates[typeURL].generation = max(state.typeStates[typeURL].generation, generation)
}

// applyUnpublishedTestResource models a resource mutation waiting for the next
// snapshot, so incremental generation can distinguish parent replacements.
func (state *nodeState) applyUnpublishedTestResource(typeURL typeurl.Index, name string, resource cache_types.Resource) typeurl.Set {
	var changes resourceChanges
	generation := state.resourceGeneration + 1
	changes.add(typeURL, name, state.resources[typeURL][name], resourceEntry{resource: resource, revision: generation.Revision(), transaction: generation.TransactionID()})
	state.commitResourceMutation(changes, generation)
	state.resourceGeneration = generation
	state.pendingPublication = &pendingPublication{generation: generation}
	return changes.typeURLs()
}
