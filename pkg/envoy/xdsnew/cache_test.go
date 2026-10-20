// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

type formattingCounter int

func (counter *formattingCounter) String() string {
	(*counter)++
	return "formatted"
}

func TestSnapshotCacheLoggerSkipsDisabledFormatting(t *testing.T) {
	var counter formattingCounter
	var infoOutput strings.Builder
	infoLogger := slog.New(slog.NewTextHandler(&infoOutput, &slog.HandlerOptions{Level: slog.LevelInfo}))
	snapshotCacheLogger(infoLogger).Debugf("value: %s", &counter)
	snapshotCacheLogger(infoLogger).Infof("value: %s", &counter)
	require.Zero(t, counter)

	var output strings.Builder
	debugLogger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	snapshotCacheLogger(debugLogger).Debugf("value: %s", &counter)
	snapshotCacheLogger(debugLogger).Infof("value: %s", &counter)
	require.Equal(t, formattingCounter(2), counter)
}

func TestGenerateSnapshotIncrementallyReusesUnchangedResources(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener1", &envoy_config_listener.Listener{Name: "listener1"})
	state.seedResource(typeurl.NetworkPolicy, "changed", &cilium.NetworkPolicy{EndpointId: 1})
	equalOriginal := &cilium.NetworkPolicy{EndpointId: 2}
	state.seedResource(typeurl.NetworkPolicy, "equal", equalOriginal)
	state.seedResource(typeurl.NetworkPolicy, "removed", &cilium.NetworkPolicy{EndpointId: 4})

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	changedPolicy := &cilium.NetworkPolicy{EndpointId: 3}
	addedPolicy := &cilium.NetworkPolicy{EndpointId: 5}
	// A different pointer with equal protobuf content must retain the already
	// published object.
	equalPolicy := proto.Clone(equalOriginal).(*cilium.NetworkPolicy)
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 1, state.resourceEntries(typeurl.NetworkPolicy),
		map[string]*cilium.NetworkPolicy{"removed": nil},
		map[string]*cilium.NetworkPolicy{
			"changed": changedPolicy,
			"equal":   equalPolicy,
			"added":   addedPolicy,
		})
	changedTypeURLs := changes.typeURLs()
	state.commitResourceMutation(changes, 1)

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)

	for typeURL := range typeurl.Count {
		if typeURL == typeurl.NetworkPolicy {
			continue
		}
		require.Equal(t,
			reflect.ValueOf(previousSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(nextSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			"resource map for %s was copied", typeURL,
		)
	}
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.Same(t,
		previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["equal"].Resource,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["equal"].Resource,
	)
	require.Same(t,
		changedPolicy,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["changed"].Resource,
	)
	require.NotContains(t, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items, "removed")
	require.Same(t,
		addedPolicy,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["added"].Resource,
	)
	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	for index := range typeurl.Count {
		require.Equal(t, fullyGenerated.GetVersion(index.URL()), next.GetVersion(index.URL()))
	}
}

func TestGenerateSnapshotFromStateIncrementallyUsesPublishedCopyOnWriteMaps(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"})
	state.resources[typeurl.NetworkPolicy] = map[string]resourceEntry{
		"changed":   {resource: &cilium.NetworkPolicy{EndpointId: 1}, revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()},
		"unchanged": {resource: &cilium.NetworkPolicy{EndpointId: 2}, revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()},
		"removed":   {resource: &cilium.NetworkPolicy{EndpointId: 3}, revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()},
	}

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	changedPolicy := &cilium.NetworkPolicy{EndpointId: 4}
	addedPolicy := &cilium.NetworkPolicy{EndpointId: 5}
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 2, state.resourceEntries(typeurl.NetworkPolicy),
		map[string]*cilium.NetworkPolicy{"removed": nil},
		map[string]*cilium.NetworkPolicy{
			"changed": changedPolicy,
			"added":   addedPolicy,
		})
	changedTypeURLs := changes.typeURLs()
	state.commitResourceMutation(changes, 2)

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)

	for typeURL := range typeurl.Count {
		if typeURL == typeurl.NetworkPolicy {
			continue
		}
		require.Equal(t,
			reflect.ValueOf(previousSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(nextSnapshot.resourceGroups[typeURL].resources.Items).Pointer(),
			"published resource map for %s was copied", typeURL,
		)
	}
	require.NotEqual(t,
		reflect.ValueOf(previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.Same(t,
		previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["unchanged"].Resource,
		nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["unchanged"].Resource,
	)
	require.Same(t, changedPolicy, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["changed"].Resource)
	require.Same(t, addedPolicy, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items["added"].Resource)
	require.NotContains(t, nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items, "removed")
	fullyGenerated, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	for index := range typeurl.Count {
		require.Equal(t, fullyGenerated.GetVersion(index.URL()), next.GetVersion(index.URL()))
	}
}

func TestGenerateSnapshotFromStateIncrementallyReusesPublishedMapAfterCoalescedABA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	state := &nodeState{}
	state.resources[typeurl.NetworkPolicy] = map[string]resourceEntry{
		"policy": {resource: policyA, revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()},
	}

	previous, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	previousSnapshot := previous.(*ciliumSnapshot)

	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 2, state.resourceEntries(typeurl.NetworkPolicy),
		(map[string]*cilium.NetworkPolicy)(nil), map[string]*cilium.NetworkPolicy{"policy": {EndpointId: 2}})
	state.commitResourceMutation(changes, 2)
	changes = resourceChanges{}
	prepareResourceMap(&changes, typeurl.NetworkPolicy, 3, state.resourceEntries(typeurl.NetworkPolicy),
		(map[string]*cilium.NetworkPolicy)(nil), map[string]*cilium.NetworkPolicy{"policy": policyA})
	changedTypeURLs := changes.typeURLs()
	state.commitResourceMutation(changes, 3)
	require.Equal(t, 1, state.typeStates[typeurl.NetworkPolicy].changedResourceNames.Len())
	require.True(t, state.typeStates[typeurl.NetworkPolicy].changedResourceNames.Has("policy"))

	next, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	require.NoError(t, err)
	nextSnapshot := next.(*ciliumSnapshot)
	require.Equal(t,
		reflect.ValueOf(previousSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
		reflect.ValueOf(nextSnapshot.resourceGroups[typeurl.NetworkPolicy].resources.Items).Pointer(),
	)
	require.NotEqual(t, previousSnapshot.GetVersion(typeurl.NetworkPolicyURL), nextSnapshot.GetVersion(typeurl.NetworkPolicyURL))
}

func TestRemoveNetworkPoliciesKeepsOtherResourceTypes(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	ctx := t.Context()
	rollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "missing", nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.True(t, c.HasNode("node1"))

	listener := &envoy_config_listener.Listener{Name: "listener"}
	err = c.ApplyResource(ctx, "node1", typeurl.Listener, "listener", listener, nil, nil)
	require.NoError(t, err)
	hosts := &cilium.NetworkPolicyHosts{Policy: 1}
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicyHosts, "hosts", hosts, nil, nil)
	require.NoError(t, err)
	for _, name := range []string{"first", "second"} {
		err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, name, &cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
		require.NoError(t, err)
	}
	before := c.resourceGeneration
	var removalRollbacks []Rollback
	for _, name := range []string{"first", "second"} {
		rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, name, nil, nil, nil)
		require.NoError(t, err)
		removalRollbacks = append(removalRollbacks, rollback)
	}
	require.Equal(t, before+2, c.resourceGeneration)
	for _, name := range []string{"first", "second"} {
		require.Nil(t, c.GetResource("node1", typeurl.NetworkPolicy, name))
	}
	resource := c.GetResource("node1", typeurl.Listener, "listener")
	require.NotNil(t, resource)
	require.Same(t, listener, resource)
	resource = c.GetResource("node1", typeurl.NetworkPolicyHosts, "hosts")
	require.NotNil(t, resource)
	require.Same(t, hosts, resource)

	noRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "first", nil, nil, nil)
	require.NoError(t, err)
	require.Nil(t, noRollback)
	require.Equal(t, before+2, c.resourceGeneration)
	for i := range slices.Backward(removalRollbacks) {
		require.NoError(t, removalRollbacks[i].Revert())
	}
	for _, name := range []string{"first", "second"} {
		require.NotNil(t, c.GetResource("node1", typeurl.NetworkPolicy, name))
	}
}

func TestApplyResourcesPublicationFailureCleansUnchangedWait(t *testing.T) {
	for _, unpublishedEndpoint := range []bool{false, true} {
		name := "published"
		if unpublishedEndpoint {
			name = "unpublished"
		}
		t.Run(name, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(t, mock)
			const nodeID = "node1"
			listener := &envoy_config_listener.Listener{Name: "listener"}
			endpoint := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}

			err := c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpoint.ClusterName: endpoint},
			}}, nil, TypeURLCallbacks{})
			require.NoError(t, err)

			// Keep an LDS watch open so the next listener change publishes immediately.
			responses := make(chan cache.Response, 1)
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
			}, stream.NewSotwSubscription(nil, true), responses)
			require.NoError(t, err)
			t.Cleanup(cancel)

			if unpublishedEndpoint {
				// An EDS-only change remains pending because only LDS has an open watch.
				endpoint = &envoy_config_endpoint.ClusterLoadAssignment{
					ClusterName: endpoint.ClusterName,
					Endpoints:   []*envoy_config_endpoint.LocalityLbEndpoints{{}},
				}
				err = c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, endpoint.ClusterName, endpoint, nil, nil)
				require.NoError(t, err)
				require.NotNil(t, c.getNodeState(nodeID).pendingPublication)
			}

			ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancelContext)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			var callbackErr error
			var waits TypeURLCallbacks
			waits.Set(typeurl.Listener, nil)
			waits.Set(typeurl.Endpoint, func(err error) { callbackErr = err })
			publicationErr := errors.New("snapshot publication failed")
			mock.setSnapshotErr = publicationErr
			rollback, err := c.ApplyResourcesWithRollback(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{
					listener.Name: {Name: listener.Name, TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND},
				},
				// The identical endpoint waits for its pending or published EDS version.
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpoint.ClusterName: endpoint},
			}}, wg, waits)
			require.ErrorIs(t, err, publicationErr)
			require.Nil(t, rollback)
			require.Zero(t, c.completionCbs.PendingCompletionCount())
			require.ErrorIs(t, wg.Wait(), publicationErr)
			require.ErrorIs(t, callbackErr, publicationErr)
			current := c.GetResource(nodeID, typeurl.Listener, listener.Name)
			require.NotNil(t, current)
			require.Same(t, listener, current)
			current = c.GetResource(nodeID, typeurl.Endpoint, endpoint.ClusterName)
			require.NotNil(t, current)
			require.Same(t, endpoint, current)
		})
	}
}

func TestPublicationInstallationRequiresSnapshotIdentity(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(fmt.Sprintf("installed=%t", installed), func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(t, mock)
			const nodeID = "node1"
			// The mock keeps the watch open so mutations finalize synchronously.
			// Otherwise the installation failure would be deferred to a request.
			cancel, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.EndpointType,
			}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancel)
			assignment := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Clusters: map[string]*envoy_config_cluster.Cluster{"cluster": {
					Name: "cluster", ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
				}},
				Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"cluster": assignment},
			}}, nil, TypeURLCallbacks{}))
			baseline := mustSnapshot(t, c, nodeID)
			publicationErr := errors.New("snapshot publication failed")
			mock.setSnapshotErr = publicationErr
			mock.storeSnapshotBeforeError = installed
			// Removing an explicit empty CLA replaces it with an identical
			// synthesized CLA. Its generation version still advances, independently
			// of whether SetSnapshot installs the new snapshot before returning an error.
			rollback, err := c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Endpoint, "cluster", nil, nil, nil)
			published := mustSnapshot(t, c, nodeID)
			if installed {
				require.NoError(t, err, "an error after installation must not undo committed state")
				require.NotNil(t, rollback)
				t.Cleanup(rollback.Finalize)
				require.NotSame(t, baseline, published)
				require.True(t, proto.Equal(assignment, published.GetResources(typeurl.Endpoint.URL())["cluster"]),
					"incremental projection may reuse the identical empty CLA")
			} else {
				require.ErrorIs(t, err, publicationErr)
				require.Nil(t, rollback)
				require.Same(t, baseline, published)
			}
			for index := range typeurl.Count {
				if installed && index == typeurl.Endpoint {
					require.NotEqual(t, baseline.GetVersion(index.URL()), published.GetVersion(index.URL()))
				} else {
					require.Equal(t, baseline.GetVersion(index.URL()), published.GetVersion(index.URL()))
				}
			}
			current := c.GetResource(nodeID, typeurl.Endpoint, "cluster")
			if installed {
				require.Nil(t, current, "the synthesized CLA belongs only to the snapshot")
			} else {
				require.Same(t, assignment, current, "failed installation must restore desired state")
			}
		})
	}
}

func TestResourceMutationPublicationFailureRestoresPreviousEntries(t *testing.T) {
	for _, mode := range []string{"mutation", "caller-revert", "response-revert"} {
		t.Run(mode, func(t *testing.T) {
			mock := newMockSnapshotCache()
			c := newInitializedTestCache(t, mock)
			const nodeID = "node1"
			node := &envoy_config_core.Node{Id: nodeID}
			// The mock keeps this watch open, making both mutations and reverts
			// finalize synchronously. Without an open watch, the injected
			// publication failure would be deferred until the next CreateWatch.
			cancel, err := c.CreateWatch(&cache.Request{Node: node, TypeUrl: envoy_resource.RouteType, VersionInfo: "e7:g99"},
				stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancel)
			initial := xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{
				"replaced": {Name: "replaced"},
				"removed":  {Name: "removed"},
			}}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: initial}, nil, TypeURLCallbacks{}))
			baseline := mustSnapshot(t, c, nodeID)
			acceptPublishedSnapshotVersions(t, c, 1, node, baseline)
			// Keep a watch available to exercise response delivery as well as
			// desired-state recovery when publication fails.
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: node, TypeUrl: envoy_resource.RouteType, ResourceNames: []string{"replaced", "removed"},
				VersionInfo: baseline.GetVersion(envoy_resource.RouteType),
			}, stream.NewSotwSubscription([]string{"replaced", "removed"}, false), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			before := maps.Clone(c.getNodeState(nodeID).resourceEntries(typeurl.Route))
			previousGeneration := c.getNodeState(nodeID).resourceGeneration
			previousTypeState := c.getNodeState(nodeID).typeStates[typeurl.Route]
			publicationErr := errors.New("snapshot publication failed")
			if mode == "mutation" {
				mock.setSnapshotErr = publicationErr
			}
			rollback, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, ResourceMutations{
				Removed: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"removed": nil}},
				Upserted: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{
					"replaced": {Name: "replaced", IgnorePortInHostMatching: true},
					"added":    {Name: "added"},
				}},
			}, nil, TypeURLCallbacks{})
			if mode == "mutation" {
				require.ErrorIs(t, err, publicationErr)
				require.Nil(t, rollback)
			} else {
				require.NoError(t, err)
				require.NotNil(t, rollback)
				before = maps.Clone(c.getNodeState(nodeID).resourceEntries(typeurl.Route))
				previousGeneration = c.getNodeState(nodeID).resourceGeneration
				previousTypeState = c.getNodeState(nodeID).typeStates[typeurl.Route]
				mock.setSnapshotErr = publicationErr
				if mode == "caller-revert" {
					require.ErrorIs(t, rollback.Revert(), publicationErr)
					// RDS omission does not convey deletion. Terminal caller
					// resolution releases the removed name's sole owner, so its
					// tombstone is pruned while desired absence is preserved.
					delete(before, "removed")
				} else {
					t.Cleanup(rollback.Finalize)
					response := publishedResponseForTest(t, c, node, typeurl.Route)
					c.completionCbs.OnStreamResponse(response.GetContext(), 1,
						response.GetRequest(),
						&discovery.DiscoveryResponse{
							TypeUrl: envoy_resource.RouteType, VersionInfo: response.GetResponseVersion(), Nonce: "rejected-routes",
						})
					require.ErrorIs(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
						Node: node, TypeUrl: envoy_resource.RouteType,
						VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "rejected-routes",
						ErrorDetail: &status.Status{Message: "rejected routes"},
					}), publicationErr)
				}
			}
			// Failure restores complete entries, not just protobufs. This covers
			// prior absence, removal tombstones, and replacement generations even
			// when a revert has no separately constructed inverse maps.
			require.Equal(t, before, c.getNodeState(nodeID).resourceEntries(typeurl.Route))
			require.Equal(t, previousGeneration, c.getNodeState(nodeID).resourceGeneration)
			// Failure restores the aggregate generation without replacing the
			// shared type record and losing its epoch or rollback ownership.
			typeState := &c.getNodeState(nodeID).typeStates[typeurl.Route]
			require.Equal(t, previousTypeState.generation, typeState.generation)
			require.Equal(t, previousTypeState.reportedEpoch, typeState.reportedEpoch)
			require.Equal(t, previousTypeState.negotiatedEpoch, typeState.negotiatedEpoch)
			require.Equal(t, previousTypeState.revertGeneration, typeState.revertGeneration,
				"failed publication must not change the restored-absence ACK fence")
			require.Greater(t, c.resourceGeneration, previousGeneration, "global generations are never rewound")
			if mode == "mutation" {
				return
			}

			// A caller's revert is terminal even on failure; fixing publication
			// must not make a duplicate call mutate desired state. Response-owned
			// recovery is independent and survives the failed stream.
			mock.setSnapshotErr = nil
			if mode == "caller-revert" {
				generation := c.resourceGeneration
				require.NoError(t, rollback.Revert())
				rollback.Finalize()
				require.Equal(t, generation, c.resourceGeneration)
				require.Equal(t, before, c.getNodeState(nodeID).resourceEntries(typeurl.Route))
				// The failed caller revert must not consume the separately owned
				// response inverse. Envoy can still reject the unchanged snapshot.
				response := publishedResponseForTest(t, c, node, typeurl.Route)
				c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
					&discovery.DiscoveryResponse{
						TypeUrl: envoy_resource.RouteType, VersionInfo: response.GetResponseVersion(), Nonce: "rejected-after-caller-revert",
					})
				require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: envoy_resource.RouteType,
					VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "rejected-after-caller-revert",
					ErrorDetail: &status.Status{Message: "rejected routes"},
				}))
			} else {
				c.completionCbs.OnStreamClosed(1, node)
				request := &discovery.DiscoveryRequest{Node: node, TypeUrl: envoy_resource.RouteType}
				require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
				snapshot := mustSnapshot(t, c, nodeID)
				c.completionCbs.OnStreamResponse(callbacks.WithSnapshotGeneration(t.Context(), c.getNodeState(nodeID).snapshotGeneration),
					2, request, &discovery.DiscoveryResponse{
						TypeUrl: envoy_resource.RouteType, VersionInfo: snapshot.GetVersion(envoy_resource.RouteType), Nonce: "retry-routes",
					})
				require.NoError(t, c.completionCbs.OnStreamRequest(2, &discovery.DiscoveryRequest{
					Node: node, TypeUrl: envoy_resource.RouteType,
					VersionInfo: baseline.GetVersion(envoy_resource.RouteType), ResponseNonce: "retry-routes",
					ErrorDetail: &status.Status{Message: "rejected routes again"},
				}))
			}
			require.Same(t, initial.Routes["replaced"], c.GetResource(nodeID, typeurl.Route, "replaced"))
			require.Nil(t, c.GetResource(nodeID, typeurl.Route, "removed"), "an unobservable RDS removal remains absent")
			require.Nil(t, c.GetResource(nodeID, typeurl.Route, "added"))
		})
	}
}

func TestNewCache(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))

	assert.NotNil(t, c.GetSnapshotCache())
	assert.NotNil(t, c.logger)
	require.True(t, c.HasNode("node1"))
	require.False(t, c.HasNode("unknown"))
	_, err := c.GetSnapshot("node1")
	require.Error(t, err, "known-node initialization must not build snapshots")
}

func TestCacheRejectsUnknownNodes(t *testing.T) {
	for _, nodeID := range []string{"unknown", ""} {
		for _, operation := range []string{"resource", "resource-with-rollback", "resources", "resources-with-rollback", "snapshot", "watch", "empty-secret-watch", "unknown-type-watch"} {
			t.Run(fmt.Sprintf("node=%q/%s", nodeID, operation), func(t *testing.T) {
				c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancel)
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				callbackCalls := 0
				callback := func(error) { callbackCalls++ }
				var waits TypeURLCallbacks
				waits.Set(typeurl.Listener, callback)
				listener := &envoy_config_listener.Listener{Name: "listener"}
				mutations := ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
				}}
				var err error
				switch operation {
				case "resource":
					err = c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, wg, callback)
				case "resource-with-rollback":
					var rollback Rollback
					rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, wg, callback)
					require.Nil(t, rollback)
				case "resources":
					err = c.ApplyResources(t.Context(), nodeID, mutations, wg, waits)
				case "resources-with-rollback":
					var rollback Rollback
					rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, mutations, wg, waits)
					require.Nil(t, rollback)
				case "snapshot":
					err = c.SetSnapshot(t.Context(), nodeID, &cache.Snapshot{})
				default:
					typeURL := typeurl.Listener.URL()
					if operation == "empty-secret-watch" {
						typeURL = typeurl.Secret.URL()
					} else if operation == "unknown-type-watch" {
						typeURL = "type.googleapis.com/example.Unknown"
					}
					var cancel func()
					cancel, err = c.CreateWatch(&cache.Request{
						Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeURL,
					}, stream.NewSotwSubscription(nil, operation == "watch"), make(chan cache.Response, 1))
					require.Nil(t, cancel)
				}
				require.ErrorContains(t, err, "unknown xDS node")
				require.False(t, c.HasNode(nodeID))
				require.True(t, c.HasNode("node1"))
				require.Nil(t, c.GetResource(nodeID, typeurl.Listener, listener.Name))
				require.Nil(t, c.GetStatusInfo(nodeID), "unknown requests must not establish watches")
				_, err = c.GetSnapshot(nodeID)
				require.Error(t, err)
				require.Zero(t, c.GetCompletionCallbacks().PendingCompletionCount())
				require.Zero(t, callbackCalls)
				require.NoError(t, wg.Wait(), "rejected mutations must not register waits")
			})
		}
	}
}

func TestCreateWatchRepublishesDesiredStateAfterClear(t *testing.T) {
	t.Run("desired-state", func(t *testing.T) {
		c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
		listener := &envoy_config_listener.Listener{Name: "listener"}
		require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, listener.Name, listener, nil, nil))
		c.ClearSnapshot("node1")
		require.True(t, c.HasNode("node1"))
		responses := make(chan cache.Response, 1)
		cancel, err := c.CreateWatch(&cache.Request{
			Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.Listener.URL(),
		}, stream.NewSotwSubscription(nil, true), responses)
		require.NoError(t, err)
		t.Cleanup(cancel)
		select {
		case response := <-responses:
			require.Contains(t, response.GetReturnedResources(), listener.Name,
				"missing delivery state must not synthesize an empty response over desired resources")
		case <-time.After(time.Second):
			t.Fatal("expected an immediate response with the desired listener")
		}
		current := c.GetResource("node1", typeurl.Listener, listener.Name)
		require.NotNil(t, current)
		require.Same(t, listener, current)
	})

}

func TestWithNodeIDsPreservesIndependentNodeState(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1", "node2"), WithNodeIDs("node1"))
	for _, nodeID := range []string{"node1", "node2"} {
		listener := &envoy_config_listener.Listener{Name: nodeID}
		require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))
		current := c.GetResource(nodeID, typeurl.Listener, listener.Name)
		require.NotNil(t, current)
		require.Same(t, listener, current)
	}
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, "node1", nil, nil, nil))
	c.ClearSnapshot("node1")
	require.True(t, c.HasNode("node1"), "empty desired and delivery state must not forget the consumer")
	require.True(t, c.HasNode("node2"))
	require.Nil(t, c.GetResource("node1", typeurl.Listener, "node1"))
	require.NotNil(t, c.GetResource("node2", typeurl.Listener, "node2"), "clearing one node must not affect another node's resources")
}

func TestSetSnapshot_Error(t *testing.T) {
	mock := newMockSnapshotCache()
	mock.setSnapshotErr = fmt.Errorf("set snapshot failed")
	c := newInitializedTestCache(t, mock)

	snap := &cache.Snapshot{}
	err := c.SetSnapshot(context.Background(), "node1", snap)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set snapshot failed")

	require.Len(t, mock.setSnapshotCalls, 1)
}

func TestGenerateSnapshotProjectsEndpoints(t *testing.T) {
	for _, tt := range []struct {
		name           string
		clusterType    envoy_config_cluster.Cluster_DiscoveryType
		serviceName    string
		assignment     *envoy_config_endpoint.ClusterLoadAssignment
		assignmentName string
	}{
		{name: "cluster-name", clusterType: envoy_config_cluster.Cluster_EDS, assignmentName: "cluster1"},
		{name: "service-name", clusterType: envoy_config_cluster.Cluster_EDS, serviceName: "service1", assignmentName: "service1"},
		{name: "explicit", clusterType: envoy_config_cluster.Cluster_EDS, assignmentName: "cluster1",
			assignment: &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "cluster1"}},
		{name: "static", clusterType: envoy_config_cluster.Cluster_STATIC},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
			upserted := xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{"cluster1": {
				Name: "cluster1", ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: tt.clusterType},
				EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: tt.serviceName},
			}}}
			if tt.assignment != nil {
				upserted.Endpoints = map[string]*envoy_config_endpoint.ClusterLoadAssignment{tt.assignmentName: tt.assignment}
			}
			require.NoError(t, c.ApplyResources(t.Context(), "node1", ResourceMutations{Upserted: upserted}, nil, TypeURLCallbacks{}))
			snapshot := requestSnapshotForTest(t, c, "node1", typeurl.Cluster)
			endpoints := snapshot.GetResources(typeurl.Endpoint.URL())
			if tt.assignmentName == "" {
				require.Empty(t, endpoints)
			} else {
				require.Len(t, endpoints, 1)
				assignment := endpoints[tt.assignmentName].(*envoy_config_endpoint.ClusterLoadAssignment)
				require.Equal(t, tt.assignmentName, assignment.ClusterName)
				require.Empty(t, assignment.Endpoints)
				if tt.assignment != nil {
					require.Same(t, tt.assignment, assignment)
				}
			}
			desired := c.GetResource("node1", typeurl.Endpoint, tt.assignmentName)
			if tt.assignment != nil {
				require.Same(t, tt.assignment, desired)
			} else {
				require.Nil(t, desired)
			}
		})
	}
}

func TestGetResourceByTypeAndName(t *testing.T) {
	c := newInitializedTestCache(t, newMockSnapshotCache())
	state := c.getNodeState("node1")
	resources := []struct {
		typeURL typeurl.Index
		name    string
		want    cache_types.Resource
	}{
		{typeurl.Endpoint, "endpoint", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "endpoint"}},
		{typeurl.Cluster, "cluster", &envoy_config_cluster.Cluster{Name: "cluster"}},
		{typeurl.Route, "route", &envoy_config_route.RouteConfiguration{Name: "route"}},
		{typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"}},
		{typeurl.Secret, "secret", &envoy_config_tls.Secret{Name: "secret"}},
		{typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1}},
		{typeurl.NetworkPolicy, "other-policy", &cilium.NetworkPolicy{EndpointId: 2}},
		{typeurl.NetworkPolicyHosts, "hosts", &cilium.NetworkPolicyHosts{}},
	}
	for _, resource := range resources {
		state.seedResource(resource.typeURL, resource.name, resource.want)
	}
	state.resources[typeurl.Listener]["removed"] = resourceEntry{revision: callbacks.Generation(1).Revision(), transaction: callbacks.Generation(1).TransactionID()}

	for _, tt := range resources {
		got := c.GetResource("node1", tt.typeURL, tt.name)
		require.NotNil(t, got, "%s %s", tt.typeURL.URL(), tt.name)
		require.Same(t, tt.want, got)
	}
	for _, tt := range []struct {
		nodeID  string
		typeURL typeurl.Index
		name    string
	}{
		{"unknown", typeurl.Listener, "listener"},
		{"node1", typeurl.Listener, "missing"},
		{"node1", typeurl.Listener, "removed"},
		{"node1", typeurl.Route, "listener"},
		{"unknown", typeurl.NetworkPolicy, "policy"},
		{"node1", typeurl.NetworkPolicy, "missing"},
		{"node1", typeurl.Count, "listener"},
	} {
		got := c.GetResource(tt.nodeID, tt.typeURL, tt.name)
		require.Nil(t, got)
	}
}

func TestClearSnapshot(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(t, mock)
	listener := &envoy_config_listener.Listener{Name: "l1"}
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, "l1", listener, nil, nil))
	c.ClearSnapshot("node1")
	require.Equal(t, []string{"node1"}, mock.clearSnapshotCalls)
	_, err := c.GetSnapshot("node1")
	require.Error(t, err)

	// Clearing delivery state must not forget desired resources or the node.
	current := c.GetResource("node1", typeurl.Listener, "l1")
	require.NotNil(t, current)
	require.Same(t, listener, current)
	require.True(t, c.HasNode("node1"))
}
func TestGenerateSnapshotProjectsSharedEDSAssignmentsWithoutChangingDesiredState(t *testing.T) {
	for _, mode := range []string{"missing", "explicit", "removed"} {
		t.Run(mode, func(t *testing.T) {
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
			clusters := map[string]*envoy_config_cluster.Cluster{
				"static": {Name: "static"},
			}
			for _, name := range []string{"cluster1", "cluster2"} {
				clusters[name] = &envoy_config_cluster.Cluster{
					Name:                 name,
					ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
					EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "shared"},
				}
			}
			explicit := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "shared"}
			upserted := xds.Resources{Clusters: clusters}
			if mode != "missing" {
				upserted.Endpoints = map[string]*envoy_config_endpoint.ClusterLoadAssignment{"shared": explicit}
			}
			require.NoError(t, c.ApplyResources(t.Context(), "node1", ResourceMutations{Upserted: upserted}, nil, TypeURLCallbacks{}))
			if mode == "removed" {
				require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Endpoint, "shared", nil, nil, nil))
			}
			snapshot := requestSnapshotForTest(t, c, "node1", typeurl.Cluster)
			endpoints := snapshot.GetResources(typeurl.Endpoint.URL())
			require.Len(t, endpoints, 1, "shared service names need just one CLA; static Clusters need none")
			require.True(t, proto.Equal(explicit, endpoints["shared"]))
			desired := c.GetResource("node1", typeurl.Endpoint, "shared")
			if mode == "explicit" {
				require.Same(t, explicit, desired)
				require.Same(t, explicit, endpoints["shared"])
			} else {
				require.Nil(t, desired, "synthesized assignments must never enter desired state")
			}
			require.Nil(t, snapshot.GetVersionMap(typeurl.Endpoint.URL()), "SotW snapshots need no per-resource versions")
		})
	}
}

func TestGenerateSnapshot_PreservesEndpointNames(t *testing.T) {
	for _, name := range []string{"service1", "namespace/service1"} {
		t.Run(name, func(t *testing.T) {
			c := newInitializedTestCache(t, newMockSnapshotCache())
			state := c.getNodeState("node1")
			cla := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
			state.seedResource(typeurl.Endpoint, name, cla)

			// Unreferenced Endpoints remain publishable; their names must not
			// cause snapshot generation to silently drop them.
			snap, err := c.generateSnapshotFromState(state)
			require.NoError(t, err)
			require.Contains(t, snap.GetResources(envoy_resource.EndpointType), name)
			require.Same(t, cla, snap.GetResources(envoy_resource.EndpointType)[name])

			// An EDS service name may differ from its Cluster's name. Preserve the
			// referenced CLA under the service name, not the Cluster's name.
			state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
				Name:                 "cluster1",
				ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
				EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: name},
			})
			snap, err = c.generateSnapshotFromState(state)
			require.NoError(t, err)
			require.Contains(t, snap.GetResources(envoy_resource.EndpointType), name)
			require.Same(t, cla, snap.GetResources(envoy_resource.EndpointType)[name])
		})
	}
}

func TestNPDSListenerCountTracksCommittedTransitions(t *testing.T) {
	observer := newTestNPDSListenerObserver("node1")
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithListenerObserver(observer), WithNodeIDs("node1"))

	listenerA := &envoy_config_listener.Listener{Name: "npds-a"}
	listenerB := &envoy_config_listener.Listener{Name: "npds-b"}
	err := c.ApplyResources(t.Context(), "node1", ResourceMutations{
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerA.Name: listenerA,
			listenerB.Name: listenerB,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 2, observer.count)

	listenerB2 := &envoy_config_listener.Listener{Name: listenerB.Name, TrafficDirection: envoy_config_core.TrafficDirection_OUTBOUND}
	rollback, err := c.ApplyResourcesWithRollback(t.Context(), "node1", ResourceMutations{
		Removed: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerA.Name: nil,
		}},
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listenerB2.Name: listenerB2,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 1, observer.count)

	require.NoError(t, rollback.Revert())
	require.Equal(t, 2, observer.count)

	rollback, err = c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.Listener, listenerB.Name, proto.Clone(listenerB).(*envoy_config_listener.Listener), nil, nil)
	require.NoError(t, err)
	require.Nil(t, rollback)
	require.Equal(t, 2, observer.count)

	listenerC := &envoy_config_listener.Listener{Name: "non-npds-c"}
	err = c.ApplyResource(t.Context(), "node1", typeurl.Listener, listenerC.Name, listenerC, nil, nil)
	require.NoError(t, err)
	require.Equal(t, 2, observer.count)
}

func TestNetworkPolicyWaitsCompleteWhenLastNPDSListenerIsRemoved(t *testing.T) {
	observer := newTestNPDSListenerObserver("node1")
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)),
		WithListenerObserver(observer), WithNodeIDs("node1"))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	listener1 := &envoy_config_listener.Listener{Name: "npds-1"}
	other := &envoy_config_listener.Listener{Name: "other"}
	err := c.ApplyResources(ctx, "node1", ResourceMutations{
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
			listener1.Name: listener1, other.Name: other,
		}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 1, observer.count)

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	firstWG := completion.NewWaitGroup(ctx)
	defer firstWG.Cancel()
	callbacks := 0
	callback := func(err error) {
		require.NoError(t, err)
		// Completion must run without the cache lock.
		c.GetResource("node1", typeurl.NetworkPolicy, "policy")
		callbacks++
	}
	policyRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, firstWG, callback)
	require.NoError(t, err)
	require.NotNil(t, policyRollback)

	noOpWG := completion.NewWaitGroup(ctx)
	defer noOpWG.Cancel()
	noOpRollback, err := c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, noOpWG, callback)
	require.NoError(t, err)
	require.Nil(t, noOpRollback)
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())

	// Replacing one NPDS listener with another in one transaction must not
	// release either wait, even though the old listener disappears.
	listener2 := &envoy_config_listener.Listener{Name: "npds-2"}
	err = c.ApplyResources(ctx, "node1", ResourceMutations{
		Removed:  xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{listener1.Name: nil}},
		Upserted: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{listener2.Name: listener2}},
	}, nil, TypeURLCallbacks{})
	require.NoError(t, err)
	require.Equal(t, 1, observer.count)
	require.Equal(t, 2, c.completionCbs.PendingCompletionCount())

	err = c.ApplyResource(ctx, "node1", typeurl.Listener, listener2.Name, nil, nil, nil)
	require.NoError(t, err)
	require.Zero(t, observer.count)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, firstWG.Wait())
	require.NoError(t, noOpWG.Wait())
	require.Equal(t, 2, callbacks)
	require.NotNil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"), "releasing the wait must not revert the policy")

	// The caller's rollback remains usable after its ACK wait was released.
	require.NoError(t, policyRollback.Revert())
	require.Nil(t, c.GetResource("node1", typeurl.NetworkPolicy, "policy"))

	noListenerWG := completion.NewWaitGroup(ctx)
	defer noListenerWG.Cancel()
	err = c.ApplyResource(ctx, "node1", typeurl.NetworkPolicy, "policy", policy, noListenerWG, callback)
	require.NoError(t, err)
	require.Zero(t, c.completionCbs.PendingCompletionCount())
	require.NoError(t, noListenerWG.Wait())
	require.Equal(t, 3, callbacks)
}

func TestNetworkPolicyPublicationFollowsWatchAvailability(t *testing.T) {
	c := newTestCache(t, "node1")
	request := &cache.Request{Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeurl.NetworkPolicyURL}
	subscription := stream.NewSotwSubscription(nil, true)
	responses := make(chan cache.Response, 1)
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1}, nil, nil))
	_, err := c.GetSnapshot("node1")
	require.Error(t, err, "desired state remains unpublished without a watch")
	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	responseA := <-responses
	subscription.SetReturnedResources(responseA.GetReturnedResources())
	cancel()
	snapshotA := mustSnapshot(t, c, "node1")

	request.VersionInfo = responseA.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 2}, nil, nil))
	responseB := <-responses
	subscription.SetReturnedResources(responseB.GetReturnedResources())
	snapshotB := mustSnapshot(t, c, "node1")
	require.NotSame(t, snapshotA, snapshotB)

	// B consumed the only watch. Further changes wait for the client's next request.
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 3}, nil, nil))
	require.Same(t, snapshotB, mustSnapshot(t, c, "node1"))
	require.Empty(t, responses)
	request.VersionInfo = responseB.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	responseC := <-responses
	require.NotSame(t, snapshotB, mustSnapshot(t, c, "node1"))
	require.NotEqual(t, responseB.GetResponseVersion(), responseC.GetResponseVersion())
	require.Empty(t, responses)
}

func TestApplyResourcesAttachesNoOpDuringResponseDelivery(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	c.setTestNodeEpochs(node.GetId(), 1)
	subscription := stream.NewSotwSubscription(nil, true)
	responses := make(chan cache.Response, 1)
	request := &cache.Request{Node: node, TypeUrl: envoy_resource.ListenerType}

	// Establish the LDS watch before publishing the listener so that its
	// response retains the exact generation propagated by SetSnapshot.
	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	emptyResponse := <-responses
	subscription.SetReturnedResources(emptyResponse.GetReturnedResources())
	acknowledgeResponse(t, c, 1, emptyResponse, "empty-listener")
	request.VersionInfo = emptyResponse.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	listener := &envoy_config_listener.Listener{Name: "listener"}
	wg1 := completion.NewWaitGroup(ctx)
	t.Cleanup(wg1.Cancel)
	err = c.ApplyResources(ctx, "node1", ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"listener": listener},
	}}, wg1, TypeURLCallbacks{})
	require.NoError(t, err)

	response := <-responses
	subscription.SetReturnedResources(response.GetReturnedResources())

	// Advance the node-wide generation with an unrelated NetworkPolicy response.
	// The listener itself still belongs to the generation carried by response.
	policyResponses := make(chan cache.Response, 1)
	policySubscription := stream.NewSotwSubscription(nil, true)
	currentSnapshot := mustSnapshot(t, c, node.GetId())
	listenerGeneration := c.getNodeState(node.GetId()).snapshotGeneration
	cancel, err = c.CreateWatch(&cache.Request{
		Node:        node,
		TypeUrl:     typeurl.NetworkPolicyURL,
		VersionInfo: currentSnapshot.GetVersion(typeurl.NetworkPolicyURL),
	}, policySubscription, policyResponses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	err = c.ApplyResource(ctx, node.GetId(), typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)

	require.NoError(t, err)
	policyResponse := <-policyResponses
	policySubscription.SetReturnedResources(policyResponse.GetReturnedResources())
	require.Greater(t, c.getNodeState(node.GetId()).snapshotGeneration, listenerGeneration)

	// The response has left the cache, but deliberately delay OnStreamResponse.
	// A semantic no-op for the same listener must attach to that response while
	// it is in the handoff window, even though an unrelated resource type has
	// advanced the node-wide generation in the meantime.
	wg2 := completion.NewWaitGroup(ctx)
	t.Cleanup(wg2.Cancel)
	err = c.ApplyResources(ctx, "node1", ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener": proto.Clone(listener).(*envoy_config_listener.Listener),
		},
	}}, wg2, TypeURLCallbacks{})
	require.NoError(t, err)
	typedWG := completion.NewWaitGroup(ctx)
	t.Cleanup(typedWG.Cancel)
	err = c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(),
		proto.Clone(listener).(*envoy_config_listener.Listener), typedWG, nil)

	require.NoError(t, err)
	request.VersionInfo = response.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case <-responses:
		t.Fatal("unexpected second response for unchanged listener contents")
	default:
	}

	c.completionCbs.OnStreamResponse(response.GetContext(), 1, response.GetRequest(),
		&discovery.DiscoveryResponse{
			VersionInfo: response.GetResponseVersion(),
			TypeUrl:     envoy_resource.ListenerType,
			Nonce:       "nonce-1",
		})
	require.NoError(t, c.completionCbs.OnStreamRequest(1, &discovery.DiscoveryRequest{
		Node:          node,
		TypeUrl:       envoy_resource.ListenerType,
		VersionInfo:   response.GetResponseVersion(),
		ResponseNonce: "nonce-1",
	}))
	acknowledgeResponse(t, c, 1, policyResponse, "policy")

	require.NoError(t, wg1.Wait())
	require.NoError(t, wg2.Wait())
	require.NoError(t, typedWG.Wait())
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestListenerRemovalPreservesUnchangedTypeWatches(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	ctx, cancelContext := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancelContext)
	node := &envoy_config_core.Node{Id: "node1"}
	c.setTestNodeEpochs(node.GetId(), 1)
	subscription := stream.NewSotwSubscription(nil, true)

	listener := &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(), listener, nil, nil)
	require.NoError(t, err)

	listenerResponses := make(chan cache.Response, 1)
	cancelListener, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
	}, subscription, listenerResponses)
	require.NoError(t, err)
	t.Cleanup(cancelListener)
	initialResponse := <-listenerResponses
	acknowledgeResponse(t, c, 1, initialResponse, "initial-listener")

	// Establish an accepted baseline for every type affected by initial full
	// snapshot generation. This leaves no cold-start rollback to obscure the
	// lifetime of the listener removal below.
	initialSnapshot := mustSnapshot(t, c, node.GetId())
	acceptPublishedSnapshotVersions(t, c, 1, node, initialSnapshot)
	c.getNodeState(node.GetId()).requireNoUnsentRollbacks(t)

	// This RDS watch is idle: removing a listener with no RDS reference does
	// not change the RDS version. It must not make the cache believe Envoy can
	// consume a new listener snapshot.
	routeResponses := make(chan cache.Response, 1)
	cancelRoute, err := c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.RouteType,
		VersionInfo: initialSnapshot.GetVersion(envoy_resource.RouteType),
	}, subscription, routeResponses)
	require.NoError(t, err)
	t.Cleanup(cancelRoute)
	initialGeneration := c.getNodeState(node.GetId()).snapshotGeneration

	err = c.ApplyResource(ctx, node.GetId(), typeurl.Listener, listener.GetName(), nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, initialGeneration, c.getNodeState(node.GetId()).snapshotGeneration)
	require.NotNil(t, c.getNodeState(node.GetId()).pendingPublication)
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly consumed the listener update")
	default:
	}

	// A listener watch now consumes the pending removal. Only LDS has a changed
	// version, so its ACK must release the last response rollback and tombstone.
	listenerResponses = make(chan cache.Response, 1)
	cancelListener, err = c.CreateWatch(&cache.Request{
		Node: node, TypeUrl: envoy_resource.ListenerType,
		VersionInfo: initialSnapshot.GetVersion(envoy_resource.ListenerType),
	}, subscription, listenerResponses)
	require.NoError(t, err)
	t.Cleanup(cancelListener)
	removalResponse := <-listenerResponses
	acknowledgeResponse(t, c, 1, removalResponse, "listener-removal")

	state := c.getNodeState(node.GetId())
	state.requireNoUnsentRollbacks(t)
	state.requireNoRollbackOwners(t)
	require.Empty(t, state.resources[typeurl.Listener],
		"an ACKed removal must not retain a tombstone for unchanged resource types")
	select {
	case <-routeResponses:
		t.Fatal("unchanged RDS watch unexpectedly received the listener update")
	default:
	}
	c.completionCbs.OnStreamClosed(1, node)
	state = c.getNodeState(node.GetId())
	require.NotNil(t, state, "known nodes persist after their last resource is removed")
	require.Empty(t, state.resources[typeurl.Listener])
	state.requireNoRollbackOwners(t)
	state.requireNoUnsentRollbacks(t)
}

func TestUpsertNetworkPolicyCompletesCoalescedABAOnCreateWatch(t *testing.T) {
	for _, mode := range []string{"tracked-final-update", "untracked-final-update"} {
		t.Run(mode, func(t *testing.T) {
			c := newCoverageCache(t)
			policyA := &cilium.NetworkPolicy{EndpointId: 1}
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policyA, nil, nil))
			s := coverageStream{cache: c, id: 1, typeURL: typeurl.NetworkPolicyURL}
			responseA := s.receive(t)
			s.reply(t, responseA, "")

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wgB := completion.NewWaitGroup(ctx)
			t.Cleanup(wgB.Cancel)
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
				&cilium.NetworkPolicy{EndpointId: 2}, wgB, nil))
			var wgA *completion.WaitGroup
			if mode == "tracked-final-update" {
				wgA = completion.NewWaitGroup(ctx)
				t.Cleanup(wgA.Cancel)
			}
			require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy", policyA, wgA, nil))
			// The contents of A are already accepted, but these new revisions
			// remain pending until a watch finalizes the coalesced publication.
			pending := 1
			if wgA != nil {
				pending++
			}
			require.Equal(t, pending, c.completionCbs.PendingCompletionCount())
			published := mustSnapshot(t, c, "coverage-node")
			require.Equal(t, responseA.VersionInfo, published.GetVersion(typeurl.NetworkPolicyURL))

			responses := make(chan cache.Response, 1)
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: "coverage-node"}, TypeUrl: typeurl.NetworkPolicyURL, VersionInfo: responseA.VersionInfo,
			}, s.sub, responses)
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			// The contents returned to A, but the wire generation advanced.
			// B's waiter must still await the ACK of the finalized response.
			s.reply(t, s.deliver(t, <-responses), "")
			require.NoError(t, wgB.Wait())
			if wgA != nil {
				require.NoError(t, wgA.Wait())
			}
			require.Zero(t, c.completionCbs.PendingCompletionCount())
			require.NotSame(t, published, mustSnapshot(t, c, "coverage-node"), "CreateWatch must publish accumulated changes")
			require.Empty(t, responses)
		})
	}
}
func TestCreateWatchPublishesEmptyPolicySnapshotForKnownNode(t *testing.T) {
	nodeID := "node-without-resources"
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs(nodeID))
	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: nodeID},
		TypeUrl:     typeurl.NetworkPolicyURL,
		VersionInfo: "stale-version",
	}
	subscription := stream.NewSotwSubscription(nil, true)
	responses := make(chan cache.Response, 1)

	cancel, err := c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	var emptyResponse cache.Response
	select {
	case emptyResponse = <-responses:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial empty snapshot")
	}
	require.Empty(t, emptyResponse.GetReturnedResources())
	require.NotEmpty(t, emptyResponse.GetResponseVersion())
	require.Empty(t, mustSnapshot(t, c, nodeID).GetResources(typeurl.NetworkPolicyURL))
	require.True(t, c.HasNode(nodeID))

	// Envoy's follow-up request acknowledges the empty version and establishes
	// the watch which will consume the node's first resource.
	subscription.SetReturnedResources(emptyResponse.GetReturnedResources())
	request = proto.Clone(request).(*cache.Request)
	request.VersionInfo = emptyResponse.GetResponseVersion()
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case <-responses:
		t.Fatal("unexpected response before the first resource update")
	default:
	}
	require.True(t, c.HasNode(nodeID))

	policy := &cilium.NetworkPolicy{EndpointId: 1}
	err = c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)
	require.True(t, c.HasNode(nodeID))

	select {
	case response := <-responses:
		require.Contains(t, response.GetReturnedResources(), "policy")
		require.Same(t, policy, mustSnapshot(t, c, nodeID).GetResources(typeurl.NetworkPolicyURL)["policy"])
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first resource update")
	}
}

func TestCreateWatchForUnknownTypeURLBypassesCiliumTracking(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(t, mock)
	request := &cache.Request{
		Node:    &envoy_config_core.Node{Id: "node1"},
		TypeUrl: "type.googleapis.com/example.Unknown",
	}

	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), make(chan cache.Response, 1))
	require.NoError(t, err)
	require.NotNil(t, cancel)
	t.Cleanup(cancel)
	require.Equal(t, 1, mock.createWatchCalls)
	require.Empty(t, mock.setSnapshotCalls)
	require.True(t, c.HasNode("node1"))
	require.True(t, c.getNodeState("node1").openWatches.Empty())
	require.Empty(t, c.watchRelays)
}

func TestApplyResourceValidatesTypeURL(t *testing.T) {
	tests := []struct {
		name     string
		typeURL  typeurl.Index
		resource proto.Message
	}{
		{name: "mismatched type", typeURL: typeurl.NetworkPolicy, resource: &envoy_config_listener.Listener{}},
		{name: "mismatched listener", typeURL: typeurl.Listener, resource: &cilium.NetworkPolicy{}},
		{name: "unsupported protobuf", typeURL: typeurl.Listener, resource: &anypb.Any{}},
		{name: "mismatched cluster", typeURL: typeurl.Cluster, resource: &envoy_config_listener.Listener{}},
		{name: "invalid index", typeURL: typeurl.Count, resource: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
			rollback, err := c.ApplyResourceWithRollback(t.Context(), "node1", tt.typeURL, "resource", tt.resource, nil, nil)
			require.Error(t, err)
			require.Nil(t, rollback)
			require.Empty(t, c.getNodeState("node1").resources)
		})
	}
}

func TestApplyResourceSupportsAllResourceTypes(t *testing.T) {
	for _, tt := range testResourceTypes() {
		t.Run(tt.typeURL.URL(), func(t *testing.T) {
			c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
			err := c.ApplyResource(t.Context(), "node1", tt.typeURL, "resource", tt.resource, nil, nil)
			require.NoError(t, err)
			actual := c.GetResource("node1", tt.typeURL, "resource")
			require.NotNil(t, actual)
			require.Same(t, tt.resource, actual)

			err = c.ApplyResource(t.Context(), "node1", tt.typeURL, "resource", tt.removed, nil, nil)
			require.NoError(t, err)
			require.Nil(t, c.GetResource("node1", tt.typeURL, "resource"))
		})
	}
}

func TestCacheRejectsEmptyResourceNames(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*cacheImpl) (Rollback, error)
	}{
		{
			name: "listener upsert",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.Listener, "", &envoy_config_listener.Listener{}, nil, nil)
			},
		},
		{
			name: "listener removal",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.Listener, "", nil, nil, nil)
			},
		},
		{
			name: "network policy upsert",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicy, "", &cilium.NetworkPolicy{}, nil, nil)
			},
		},
		{
			name: "network policy hosts upsert",
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourceWithRollback(t.Context(), "node1", typeurl.NetworkPolicyHosts, "", &cilium.NetworkPolicyHosts{}, nil, nil)
			},
		},
	}

	genericResources := []struct {
		name      string
		resources xds.Resources
	}{
		{name: "listener", resources: xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{"": {}}}},
		{name: "route", resources: xds.Resources{Routes: map[string]*envoy_config_route.RouteConfiguration{"": {}}}},
		{name: "cluster", resources: xds.Resources{Clusters: map[string]*envoy_config_cluster.Cluster{"": {}}}},
		{name: "endpoint", resources: xds.Resources{Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"": {}}}},
		{name: "secret", resources: xds.Resources{Secrets: map[string]*envoy_config_tls.Secret{"": {}}}},
	}
	for _, tt := range genericResources {
		tests = append(tests, struct {
			name  string
			apply func(*cacheImpl) (Rollback, error)
		}{
			name: "generic " + tt.name,
			apply: func(c *cacheImpl) (Rollback, error) {
				return c.ApplyResourcesWithRollback(t.Context(), "node1", ResourceMutations{Upserted: tt.resources}, nil, TypeURLCallbacks{})
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
			rollback, err := tt.apply(c)
			require.ErrorContains(t, err, "resource name must not be empty")
			require.Nil(t, rollback)
			require.Empty(t, c.getNodeState("node1").resources)
		})
	}
}

func TestCreateWatch_DelegatesToSnapshotCache(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(t, mock)

	respChan := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: envoy_resource.ListenerType}, nil, respChan)
	require.NoError(t, err)
	require.NotNil(t, cancel)

	assert.Equal(t, 1, mock.createWatchCalls)
}

func TestCreateWatchPublishesKnownNodeState(t *testing.T) {
	for _, clientVersion := range []string{"", "stale-version"} {
		t.Run(fmt.Sprintf("client-version=%q", clientVersion), func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
			const nodeID = "node-without-resources"
			c := newCache(logger, WithNodeIDs(nodeID))
			node := &envoy_config_core.Node{Id: nodeID}
			subscription := stream.NewSotwSubscription(nil, true)
			responses := make(chan cache.Response, 1)

			firstRequest := &cache.Request{
				Node: node, TypeUrl: envoy_resource.ListenerType, VersionInfo: clientVersion,
			}
			cancel, err := c.CreateWatch(firstRequest, subscription, responses)
			require.NoError(t, err)
			t.Cleanup(cancel)
			firstResponse := <-responses
			require.Empty(t, firstResponse.GetReturnedResources())
			snapshot, err := c.GetSnapshot(nodeID)
			require.NoError(t, err)
			require.Equal(t, snapshot.GetVersion(envoy_resource.ListenerType), firstResponse.GetResponseVersion())
			require.True(t, c.HasNode(nodeID))

			subscription.SetReturnedResources(firstResponse.GetReturnedResources())
			secondRequest := &cache.Request{
				Node: node, TypeUrl: envoy_resource.ListenerType, VersionInfo: firstResponse.GetResponseVersion(),
			}
			cancel, err = c.CreateWatch(secondRequest, subscription, responses)
			require.NoError(t, err)
			t.Cleanup(cancel)
			require.Equal(t, 1, c.GetStatusInfo(nodeID).GetNumWatches())
			select {
			case <-responses:
				t.Fatal("current version must establish a watch, not send another response")
			default:
			}

			err = c.ApplyResource(t.Context(), nodeID, typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"}, nil, nil)
			require.NoError(t, err)
			require.Equal(t, mustSnapshot(t, c, nodeID).GetVersion(envoy_resource.ListenerType), (<-responses).GetResponseVersion())
		})
	}

}

func TestFirstWatchPublishesDesiredResourcesOfOtherTypes(t *testing.T) {
	const nodeID = "node-with-policy"
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.NetworkPolicy, "policy", policy, nil, nil))
	_, err := c.GetSnapshot(nodeID)
	require.Error(t, err, "the policy must remain pending before any watch exists")

	// LDS is empty, but its first watch must finalize the real node's complete
	// desired state rather than publish a detached, entirely empty snapshot.
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.Len(t, responses, 1)
	response := <-responses
	require.Empty(t, response.GetReturnedResources())
	snapshot := mustSnapshot(t, c, nodeID)
	require.Equal(t, snapshot.GetVersion(envoy_resource.ListenerType), response.GetResponseVersion())
	require.Same(t, policy, snapshot.GetResources(typeurl.NetworkPolicyURL)["policy"])

	cancel, err = c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: typeurl.NetworkPolicyURL,
	}, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.Len(t, responses, 1)
	require.Contains(t, (<-responses).GetReturnedResources(), "policy")
	require.Same(t, snapshot, mustSnapshot(t, c, nodeID), "the second watch must reuse the complete baseline")
}

func TestCreateWatchPreservesExistingNonemptySnapshot(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	const nodeID = "node-with-listener"
	c := newCache(logger, WithNodeIDs(nodeID))
	listener := &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil)
	require.NoError(t, err)
	request := &cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}
	// The first watch finalizes the pending state. A subsequent watch must use
	// that published snapshot rather than replacing it.
	initialResponses := make(chan cache.Response, 1)
	initialCancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), initialResponses)
	require.NoError(t, err)
	t.Cleanup(initialCancel)
	<-initialResponses
	snapshot := mustSnapshot(t, c, nodeID)

	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case response := <-responses:
		require.Contains(t, response.GetReturnedResources(), "listener")
		require.Equal(t, snapshot.GetVersion(envoy_resource.ListenerType), response.GetResponseVersion())
	default:
		t.Fatal("expected an immediate response containing the existing listener")
	}

	storedSnapshot, err := c.GetSnapshot(nodeID)
	require.NoError(t, err)
	require.Same(t, snapshot, storedSnapshot, "the watch must not replace the published snapshot")
	storedListener := c.GetResource(nodeID, typeurl.Listener, listener.Name)
	require.NotNil(t, storedListener)
	require.Same(t, listener, storedListener, "the watch must not replace desired resources")
}

func TestCreateWatchInitialSnapshotPublicationError(t *testing.T) {
	for _, stored := range []bool{false, true} {
		t.Run(fmt.Sprintf("stored=%t", stored), func(t *testing.T) {
			mock := newMockSnapshotCache()
			mock.setSnapshotErr = errors.New("response delivery failed")
			mock.storeSnapshotBeforeError = stored
			c := newInitializedTestCache(t, mock)
			request := &cache.Request{
				Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: envoy_resource.ListenerType,
			}
			cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			if cancel != nil {
				t.Cleanup(cancel)
			}
			if stored {
				require.NoError(t, err, "a stored snapshot is committed despite a delivery error")
			} else {
				require.ErrorContains(t, err, "response delivery failed")
			}
			require.True(t, c.HasNode("node1"))
		})
	}
}

func TestWithNodeIDsIgnoresEmptyID(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("", "node1", "node1"))
	require.False(t, c.HasNode(""))
	require.True(t, c.HasNode("node1"))
	_, err := c.GetSnapshot("node1")
	require.Error(t, err, "registration must not generate a snapshot")
}

func TestCreateWatchRejectsNilRequest(t *testing.T) {
	mock := newMockSnapshotCache()
	c := newInitializedTestCache(t, mock)
	cancel, err := c.CreateWatch(nil, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
	require.ErrorContains(t, err, "nil xDS request")
	require.Nil(t, cancel)
	require.Zero(t, mock.createWatchCalls)
	require.Empty(t, mock.getSnapshotCalls)
	require.Empty(t, mock.setSnapshotCalls)
	require.True(t, c.getNodeState("node1").openWatches.Empty())
}

func TestCreateWatchEmptyNamedSubscription(t *testing.T) {
	for _, resourceType := range testResourceTypes() {
		typeURL, resource := resourceType.typeURL, resourceType.resource
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/populated=%t", typeURL.URL(), populated), func(t *testing.T) {
				c := newTestCache(t, "node1")
				if populated {
					require.NoError(t, c.ApplyResource(t.Context(), "node1", typeURL, "resource", resource, nil, nil))
				}
				before, beforeErr := c.GetSnapshot("node1")
				request := &cache.Request{
					Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeURL.URL(),
				}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, false), responses)
				require.NoError(t, err)
				require.NotNil(t, cancel)
				cancel()
				cancel()
				require.Empty(t, responses, "an empty subscription must not receive full state")
				require.True(t, c.getNodeState("node1").openWatches.Empty())
				require.Empty(t, c.watchRelays)
				after, err := c.GetSnapshot("node1")
				if beforeErr != nil {
					require.Error(t, err, "an empty subscription must not trigger snapshot publication")
				} else {
					require.NoError(t, err)
					require.Same(t, before, after)
				}

				// A named subscription must still be answered, even when its
				// resource does not exist yet. A following current-version watch
				// can then consume the resource's first update.
				request.ResourceNames = []string{"resource"}
				subscription := stream.NewSotwSubscription(request.ResourceNames, false)
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				response := <-responses
				require.Equal(t, populated, len(response.GetReturnedResources()) == 1)
				request.VersionInfo = response.GetResponseVersion()
				subscription.SetReturnedResources(response.GetReturnedResources())
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				require.Equal(t, 1, c.GetStatusInfo("node1").GetNumWatches())
				if !populated {
					require.NoError(t, c.ApplyResource(t.Context(), "node1", typeURL, "resource", resource, nil, nil))
					require.Contains(t, (<-responses).GetReturnedResources(), "resource")
				}
				cancel()

				// After an explicit subscription, empty names are an unsubscribe,
				// not a request to fall back to wildcard mode.
				subscription.SetResourceSubscription(nil)
				request.ResourceNames = nil
				cancel, err = c.CreateWatch(request, subscription, responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				require.Empty(t, responses)
				require.True(t, c.getNodeState("node1").openWatches.Empty())
				require.Zero(t, c.GetStatusInfo("node1").GetNumWatches())
			})
		}
	}
}

func TestCreateWatchPreservesWildcardSubscriptions(t *testing.T) {
	resources := typeurl.Slots[proto.Message]{}
	for _, resourceType := range testResourceTypes() {
		resources[resourceType.typeURL] = resourceType.resource
	}
	// Include LDS/RDS and CDS/EDS pairs in the wildcard response.
	resources[typeurl.Cluster] = testEDSCluster("resource", "")
	resources[typeurl.Listener] = testRDSListener(t, "resource", "resource")
	mutations := ResourceMutations{Upserted: xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{"resource": resources[typeurl.Listener].(*envoy_config_listener.Listener)},
		Routes:    map[string]*envoy_config_route.RouteConfiguration{"resource": resources[typeurl.Route].(*envoy_config_route.RouteConfiguration)},
		Clusters:  map[string]*envoy_config_cluster.Cluster{"resource": resources[typeurl.Cluster].(*envoy_config_cluster.Cluster)},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{"resource": resources[typeurl.Endpoint].(*envoy_config_endpoint.ClusterLoadAssignment)},
		Secrets:   map[string]*envoy_config_tls.Secret{"resource": resources[typeurl.Secret].(*envoy_config_tls.Secret)},
	}}
	for index, resource := range resources {
		typeURL := typeurl.Index(index)
		for _, subscription := range []struct {
			name  string
			names []string
		}{
			{name: "implicit"},
			{name: "explicit", names: []string{"*"}},
			{name: "mixed", names: []string{"missing", "*"}},
		} {
			t.Run(fmt.Sprintf("%s/%s", typeURL.URL(), subscription.name), func(t *testing.T) {
				c := newTestCache(t, "node1")
				require.NoError(t, c.ApplyResources(t.Context(), "node1", mutations, nil, NewTypeURLCallbacks()))
				require.NoError(t, c.ApplyResource(t.Context(), "node1", typeURL, "resource", resource, nil, nil))
				request := &cache.Request{
					Node: &envoy_config_core.Node{Id: "node1"}, TypeUrl: typeURL.URL(), ResourceNames: subscription.names,
				}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(subscription.names, len(subscription.names) == 0), responses)
				require.NoError(t, err)
				t.Cleanup(cancel)
				select {
				case response := <-responses:
					require.Contains(t, response.GetReturnedResources(), "resource")
					require.Empty(t, response.GetRequest().ResourceNames)
					if len(subscription.names) == 0 {
						require.Same(t, request, response.GetRequest(), "implicit wildcards need no copy")
					} else {
						require.NotSame(t, request, response.GetRequest())
					}
				default:
					t.Fatal("expected an immediate wildcard response")
				}
				require.Equal(t, subscription.names, request.ResourceNames, "wildcard normalization must not mutate the caller's request")
			})
		}

	}
}

func TestCreateWatchWildcardNormalizationPreservesRequestFields(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"}, nil, nil))
	request := &cache.Request{
		VersionInfo:   "client-version",
		Node:          &envoy_config_core.Node{Id: "node1", Cluster: "cluster", Locality: &envoy_config_core.Locality{Zone: "zone"}},
		ResourceNames: []string{"*"},
		ResourceLocators: []*discovery.ResourceLocator{{
			Name: "locator", DynamicParameters: map[string]string{"key": "value"},
		}},
		TypeUrl:       envoy_resource.ListenerType,
		ResponseNonce: "nonce",
		ErrorDetail:   &status.Status{Code: 3, Message: "diagnostic"},
	}
	original := proto.Clone(request).(*cache.Request)
	expected := proto.Clone(request).(*cache.Request)
	expected.ResourceNames = nil
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(request.ResourceNames, false), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case response := <-responses:
		normalized := response.GetRequest()
		require.True(t, proto.Equal(expected, normalized), "only resource names may change")
		require.True(t, proto.Equal(original, request), "the caller's protobuf must remain unchanged")
		require.Same(t, request.Node, normalized.Node)
		require.Same(t, request.ErrorDetail, normalized.ErrorDetail)
		require.Same(t, request.ResourceLocators[0], normalized.ResourceLocators[0])
	default:
		t.Fatal("expected an immediate wildcard response")
	}
}

func TestSetAndGetSnapshotRoundTrip(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "l1", &envoy_config_listener.Listener{Name: "l1"})
	state.seedResource(typeurl.Cluster, "c1", &envoy_config_cluster.Cluster{Name: "c1"})
	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, c.SetSnapshot(t.Context(), "node1", snapshot))
	retrieved, err := c.GetSnapshot("node1")
	require.NoError(t, err)
	require.Same(t, snapshot, retrieved)
}
func TestEmptyKnownNodeRemovalIsNoOp(t *testing.T) {
	for _, bulkNilUpsert := range []bool{false, true} {
		t.Run(fmt.Sprintf("nil-upsert=%t", bulkNilUpsert), func(t *testing.T) {
			c := newTestCache(t, "node1")
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			callbackCalls := 0
			callback := func(err error) { require.NoError(t, err); callbackCalls++ }
			var mutations ResourceMutations
			var waits TypeURLCallbacks
			waitGroup := wg
			if bulkNilUpsert {
				mutations.Upserted.Routes = map[string]*envoy_config_route.RouteConfiguration{"route": nil}
				waitGroup = nil
			} else {
				mutations.Removed.Listeners = map[string]*envoy_config_listener.Listener{"listener": nil}
				waits.Set(typeurl.Listener, callback)
			}
			rollback, err := c.ApplyResourcesWithRollback(ctx, "node1", mutations, waitGroup, waits)
			require.NoError(t, err)
			require.Nil(t, rollback)
			if !bulkNilUpsert {
				rollback, err = c.ApplyResourceWithRollback(ctx, "node1", typeurl.NetworkPolicy, "policy", nil, wg, callback)
				require.NoError(t, err)
				require.Nil(t, rollback)
				require.Equal(t, 2, callbackCalls)
			} else {
				require.Zero(t, callbackCalls)
			}
			require.NoError(t, wg.Wait())
			require.True(t, c.HasNode("node1"))
			require.Zero(t, c.completionCbs.PendingCompletionCount())
			require.Empty(t, c.getNodeState("node1").resources)
		})
	}
}
func TestUntrackedPublicationPreservesEarlierUpdate(t *testing.T) {
	for _, test := range []struct {
		name           string
		installed      bool
		pendingRemoval bool
	}{
		{name: "before-store"},
		{name: "after-store", installed: true},
		{name: "pending-removal", pendingRemoval: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := newCoverageCache(t)
			mock := newMockSnapshotCache()
			if !test.pendingRemoval {
				c.replaceSnapshotCache(t, mock)
			}
			const nodeID = "coverage-node"
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			var wg *completion.WaitGroup
			var callback func(error)
			done := make(chan error, 1)
			index := typeurl.NetworkPolicy
			var first proto.Message = &cilium.NetworkPolicy{EndpointId: 1}
			if test.pendingRemoval {
				index = typeurl.Cluster
				first = &envoy_config_cluster.Cluster{Name: "resource"}
			} else {
				wg = completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				callback = func(err error) { done <- err }
			}
			require.NoError(t, c.ApplyResource(ctx, nodeID, index, "resource", first, wg, callback))
			s := coverageStream{cache: c, id: 1, typeURL: index.URL()}
			watchType := index
			if test.pendingRemoval {
				s.reply(t, s.receive(t), "")
				lds := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
				lds.reply(t, lds.receive(t), "")
				require.NoError(t, c.ApplyResource(ctx, nodeID, index, "resource", nil, nil, nil))
				// The next update changes LDS while response recovery owns the
				// unacknowledged Cluster removal.
				watchType = typeurl.Listener
			}
			if !test.pendingRemoval {
				requestSnapshotForTest(t, c, nodeID, index)
			}
			previous := mustSnapshot(t, c, nodeID)
			mock.snapshots[nodeID] = previous
			mock.storeSnapshotBeforeError = test.installed
			restore := c.replaceSnapshotCache(t, mock)
			// Keep an outstanding watch across the failed publication while
			// preserving the earlier recovery state.
			cancelWatch, err := c.CreateWatch(&cache.Request{
				Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: watchType.URL(),
				VersionInfo: previous.GetVersion(watchType.URL()),
			}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancelWatch)

			publicationErr := errors.New("snapshot publication failed")
			mock.setSnapshotErr = publicationErr
			var replacement proto.Message = &cilium.NetworkPolicy{EndpointId: 2}
			if test.pendingRemoval {
				replacement = &envoy_config_listener.Listener{Name: "resource"}
			}
			err = c.ApplyResource(ctx, nodeID, watchType, "resource", replacement, nil, nil)
			if test.installed {
				// go-control-plane can report a delivery error after installing
				// the snapshot. That update must remain committed and ACKable.
				require.NoError(t, err)
				require.Same(t, replacement, c.GetResource(nodeID, watchType, "resource"))
				require.NotSame(t, previous, mustSnapshot(t, c, nodeID))
			} else {
				require.ErrorIs(t, err, publicationErr)
				require.Same(t, previous, mustSnapshot(t, c, nodeID))
				if test.pendingRemoval {
					require.Nil(t, c.GetResource(nodeID, watchType, "resource"))
				} else {
					require.Same(t, first, c.GetResource(nodeID, index, "resource"))
				}
			}
			if test.pendingRemoval {
				require.Nil(t, c.GetResource(nodeID, index, "resource"))
				restore()
				response := s.receive(t)
				require.Empty(t, response.Resources)
				s.reply(t, response, "Cluster removal rejected")
				require.Same(t, first, c.GetResource(nodeID, index, "resource"),
					"publication recovery must retain ownership so the pending NACK can restore the removal")
				c.getNodeState(nodeID).requireNoRollbackOwners(t)
				return
			}
			requireCoveragePending(t, done)
			mock.setSnapshotErr = nil
			published := mustSnapshot(t, c, nodeID)
			ackNetworkPolicyVersion(t, c, nodeID, published.GetVersion(typeurl.NetworkPolicyURL))
			require.NoError(t, wg.Wait())
			require.NoError(t, <-done)
			require.Empty(t, done)
			require.Zero(t, c.completionCbs.PendingCompletionCount())
		})
	}
}

func TestGenerateSnapshotNewEDSClusterSharingEndpointBumpsVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{
		Name: "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	changedTypeURLs := state.applyUnpublishedTestResource(typeurl.Cluster, "cluster2", &envoy_config_cluster.Cluster{
		Name: "cluster2",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
	require.Same(t, before.GetResources(envoy_resource.EndpointType)["backend"], after.GetResources(envoy_resource.EndpointType)["backend"])
}

func TestGenerateSnapshotNewQualifiedEDSClusterSharingEndpointBumpsVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	state.seedResource(typeurl.Cluster, "cec-a/shared-cluster", &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	changedTypeURLs := state.applyUnpublishedTestResource(typeurl.Cluster, "cec-b/shared-cluster", &envoy_config_cluster.Cluster{
		Name: "shared-cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{
			Type: envoy_config_cluster.Cluster_EDS,
		},
		EdsClusterConfig: &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	})

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotExistingClusterUpdateBumpsEndpointVersion(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	state := &nodeState{epoch: 1, resourceGeneration: 10}
	state.seedResourceAtGeneration(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"}, 9)
	state.seedResourceAtGeneration(typeurl.Endpoint, "unrelated", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "unrelated"}, 9)
	cluster := &envoy_config_cluster.Cluster{
		Name:                 "cluster1",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
	}
	state.seedResourceAtGeneration(typeurl.Cluster, "cluster1", cluster, 10)
	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	updatedCluster := proto.Clone(cluster).(*envoy_config_cluster.Cluster)
	updatedCluster.AltStatName = "updated"
	changed := state.applyUnpublishedTestResource(typeurl.Cluster, "cluster1", updatedCluster)
	after, err := c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, "e1:g11", after.GetVersion(envoy_resource.EndpointType))
	require.Same(t, before.GetResources(envoy_resource.EndpointType)["backend"], after.GetResources(envoy_resource.EndpointType)["backend"])

	// A real EDS update after the CDS update has the newer generation. The
	// forced aggregate version must never move it backwards.
	changed = changed.Union(state.applyUnpublishedTestResource(typeurl.Endpoint, "backend",
		&envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend", Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{}}}))
	after, err = c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, "e1:g12", after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotRemovedClusterDoesNotBumpEndpointVersion(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Endpoint, "backend", &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: "backend"})
	for _, name := range []string{"cluster1", "cluster2"} {
		state.seedResource(typeurl.Cluster, name, &envoy_config_cluster.Cluster{
			Name:                 name,
			ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
			EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: "backend"},
		})
	}
	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	changed := state.applyUnpublishedTestResource(typeurl.Cluster, "cluster2", nil)
	after, err := c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.EndpointType), after.GetVersion(envoy_resource.EndpointType))
}

func TestGenerateSnapshotNewRDSListenerDoesNotBumpRouteVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Route, "route1", &envoy_config_route.RouteConfiguration{Name: "route1"})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
						RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{
							Rds: &envoy_config_http.Rds{RouteConfigName: "route1"},
						},
					}),
				},
			}},
		}},
	}
	changedTypeURLs := state.applyUnpublishedTestResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.RouteType), after.GetVersion(envoy_resource.RouteType))
}

func TestGenerateSnapshotExistingListenerUpdateKeepsReferencedRouteVersions(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	state := &nodeState{epoch: 1, resourceGeneration: 10}
	state.seedResourceAtGeneration(typeurl.Route, "route1", &envoy_config_route.RouteConfiguration{Name: "route1"}, 9)
	state.seedResourceAtGeneration(typeurl.Route, "unrelated", &envoy_config_route.RouteConfiguration{Name: "unrelated"}, 9)
	listener := &envoy_config_listener.Listener{Name: "listener1", FilterChains: []*envoy_config_listener.FilterChain{{
		Filters: []*envoy_config_listener.Filter{{
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
				RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{RouteConfigName: "route1"}},
			})},
		}},
	}}}
	state.seedResourceAtGeneration(typeurl.Listener, "listener1", listener, 10)
	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	updatedListener := proto.Clone(listener).(*envoy_config_listener.Listener)
	updatedListener.TrafficDirection = envoy_config_core.TrafficDirection_INBOUND
	changed := state.applyUnpublishedTestResource(typeurl.Listener, "listener1", updatedListener)
	after, err := c.generateSnapshotFromStateIncrementally(state, before, changed)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.RouteType), after.GetVersion(envoy_resource.RouteType))
	require.Same(t, before.GetResources(envoy_resource.RouteType)["route1"], after.GetResources(envoy_resource.RouteType)["route1"])
}

// The live-Envoy test observes a fresh EDS response after a Cluster changes,
// but an unchanged RDS resource needs no response after a Listener changes.
// Exercise both watch paths here without starting Envoy in every test run.
func TestParentReplacementReplaysOnlyEndpointWatches(t *testing.T) {
	for _, parent := range []typeurl.Index{typeurl.Cluster, typeurl.Listener} {
		t.Run(parent.URL(), func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			c := newCache(logger, WithNodeIDs("node1"))
			const nodeID = "node1"
			node := &envoy_config_core.Node{Id: nodeID}
			const childName = "child"
			var child typeurl.Index
			var parentName string
			var updated cache_types.Resource
			var initial xds.Resources
			if parent == typeurl.Cluster {
				child = typeurl.Endpoint
				parentName = "cluster"
				initial = xds.Resources{
					Clusters: map[string]*envoy_config_cluster.Cluster{parentName: {
						Name:                 parentName,
						ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
						EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: childName},
					}},
					Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{childName: {ClusterName: childName}},
				}
				updated = proto.Clone(initial.Clusters[parentName]).(*envoy_config_cluster.Cluster)
				updated.(*envoy_config_cluster.Cluster).AltStatName = "replacement"
			} else {
				child = typeurl.Route
				parentName = "listener"
				initial = xds.Resources{
					Listeners: map[string]*envoy_config_listener.Listener{parentName: {
						Name: parentName,
						FilterChains: []*envoy_config_listener.FilterChain{{Filters: []*envoy_config_listener.Filter{{
							Name: "envoy.filters.network.http_connection_manager",
							ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t, &envoy_config_http.HttpConnectionManager{
								RouteSpecifier: &envoy_config_http.HttpConnectionManager_Rds{Rds: &envoy_config_http.Rds{RouteConfigName: childName}},
							})},
						}}}},
					}},
					Routes: map[string]*envoy_config_route.RouteConfiguration{childName: {Name: childName}},
				}
				updated = proto.Clone(initial.Listeners[parentName]).(*envoy_config_listener.Listener)
				updated.(*envoy_config_listener.Listener).TrafficDirection = envoy_config_core.TrafficDirection_INBOUND
			}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: initial}, nil, TypeURLCallbacks{}))

			sotwResponses := make(chan cache.Response, 1)
			sotwSubscription := stream.NewSotwSubscription([]string{childName}, false)
			request := &cache.Request{Node: node, TypeUrl: child.URL(), ResourceNames: []string{childName}}
			cancel, err := c.CreateWatch(request, sotwSubscription, sotwResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			initialSotW := <-sotwResponses
			sotwSubscription.SetReturnedResources(initialSotW.GetReturnedResources())
			parentResponses := make(chan cache.Response, 1)
			parentSubscription := stream.NewSotwSubscription(nil, true)
			parentRequest := &cache.Request{Node: node, TypeUrl: parent.URL()}
			cancel, err = c.CreateWatch(parentRequest, parentSubscription, parentResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			initialParent := <-parentResponses
			parentSubscription.SetReturnedResources(initialParent.GetReturnedResources())

			request.VersionInfo = initialSotW.GetResponseVersion()
			cancel, err = c.CreateWatch(request, sotwSubscription, sotwResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			parentRequest.VersionInfo = initialParent.GetResponseVersion()
			cancel, err = c.CreateWatch(parentRequest, parentSubscription, parentResponses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, parent, parentName, updated, nil, nil))
			require.Eventually(t, func() bool { return len(parentResponses) != 0 }, time.Second, time.Millisecond)
			<-parentResponses
			if parent == typeurl.Cluster {
				require.Eventually(t, func() bool { return len(sotwResponses) != 0 }, time.Second, time.Millisecond)
				response := <-sotwResponses
				require.NotEqual(t, initialSotW.GetResponseVersion(), response.GetResponseVersion())
			} else {
				require.Empty(t, sotwResponses)
				require.Equal(t, initialSotW.GetResponseVersion(), mustSnapshot(t, c, nodeID).GetVersion(child.URL()))
			}
		})
	}
}

func TestNewClusterSharingEndpointReplaysWatches(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	c := newCache(logger, WithNodeIDs("node1"))
	const nodeID = "node1"
	const endpointName = "shared-endpoint"
	node := &envoy_config_core.Node{Id: nodeID}
	cluster := func(name string) *envoy_config_cluster.Cluster {
		return &envoy_config_cluster.Cluster{
			Name:                 name,
			ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
			EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: endpointName},
		}
	}
	require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
		Clusters:  map[string]*envoy_config_cluster.Cluster{"first": cluster("first")},
		Endpoints: map[string]*envoy_config_endpoint.ClusterLoadAssignment{endpointName: {ClusterName: endpointName}},
	}}, nil, TypeURLCallbacks{}))

	endpointRequest := &cache.Request{Node: node, TypeUrl: envoy_resource.EndpointType, ResourceNames: []string{endpointName}}
	endpointSubscription := stream.NewSotwSubscription([]string{endpointName}, false)
	endpointResponses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(endpointRequest, endpointSubscription, endpointResponses)
	require.NoError(t, err)
	if cancel != nil {
		t.Cleanup(cancel)
	}
	initialEndpoint := <-endpointResponses
	endpointSubscription.SetReturnedResources(initialEndpoint.GetReturnedResources())

	clusterRequest := &cache.Request{Node: node, TypeUrl: envoy_resource.ClusterType}
	clusterSubscription := stream.NewSotwSubscription(nil, true)
	clusterResponses := make(chan cache.Response, 1)
	cancel, err = c.CreateWatch(clusterRequest, clusterSubscription, clusterResponses)
	require.NoError(t, err)
	if cancel != nil {
		t.Cleanup(cancel)
	}
	initialCluster := <-clusterResponses
	clusterSubscription.SetReturnedResources(initialCluster.GetReturnedResources())

	endpointRequest.VersionInfo = initialEndpoint.GetResponseVersion()
	cancel, err = c.CreateWatch(endpointRequest, endpointSubscription, endpointResponses)
	require.NoError(t, err)
	if cancel != nil {
		t.Cleanup(cancel)
	}
	clusterRequest.VersionInfo = initialCluster.GetResponseVersion()
	cancel, err = c.CreateWatch(clusterRequest, clusterSubscription, clusterResponses)
	require.NoError(t, err)
	if cancel != nil {
		t.Cleanup(cancel)
	}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "second", cluster("second"), nil, nil))
	require.Eventually(t, func() bool { return len(clusterResponses) != 0 }, time.Second, time.Millisecond)
	<-clusterResponses
	require.Eventually(t, func() bool { return len(endpointResponses) != 0 }, time.Second, time.Millisecond)
	require.NotEqual(t, initialEndpoint.GetResponseVersion(), (<-endpointResponses).GetResponseVersion())
}

func TestDeliverResponsesOrdersADSParentBeforeChild(t *testing.T) {
	c := &cacheImpl{}
	var sotwResponses []cache.Response
	for _, typeURL := range []string{
		envoy_resource.EndpointType,
		envoy_resource.RouteType,
		envoy_resource.ClusterType,
		envoy_resource.ListenerType,
	} {
		// The backend may produce these responses in randomized watch-map order.
		sotwResponses = append(sotwResponses, &cache.RawResponse{Request: &discovery.DiscoveryRequest{TypeUrl: typeURL}})
	}
	// Coalesced responses for a stream share one relay/channel.
	orderedSotW := make(chan cache.Response, 4)
	c.deliverResponses([]responseDelivery{{channel: orderedSotW, responses: sotwResponses}})
	for _, want := range []string{
		envoy_resource.ClusterType,
		envoy_resource.EndpointType,
		envoy_resource.ListenerType,
		envoy_resource.RouteType,
	} {
		require.Equal(t, want, (<-orderedSotW).GetRequest().GetTypeUrl())
	}
}

func TestGenerateSnapshotNewSDSListenerDoesNotBumpSecretVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Secret, "secret1", &envoy_config_tls.Secret{Name: "secret1"})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			TransportSocket: &envoy_config_core.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &envoy_config_core.TransportSocket_TypedConfig{
					TypedConfig: mustAny(t, &envoy_config_tls.DownstreamTlsContext{
						CommonTlsContext: &envoy_config_tls.CommonTlsContext{
							TlsCertificateSdsSecretConfigs: []*envoy_config_tls.SdsSecretConfig{{
								Name: "secret1",
							}},
						},
					}),
				},
			},
		}},
	}
	changedTypeURLs := state.applyUnpublishedTestResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.SecretType), after.GetVersion(envoy_resource.SecretType))
}

func TestGenerateSnapshotNewTCPProxyListenerDoesNotBumpClusterVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Cluster, "cluster1", &envoy_config_cluster.Cluster{Name: "cluster1"})

	before, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	listener := &envoy_config_listener.Listener{
		Name: "listener1",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name: "envoy.filters.network.tcp_proxy",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{
					TypedConfig: mustAny(t, &envoy_extensions_filters_network_tcp_proxy.TcpProxy{
						ClusterSpecifier: &envoy_extensions_filters_network_tcp_proxy.TcpProxy_Cluster{Cluster: "cluster1"},
					}),
				},
			}},
		}},
	}
	changedTypeURLs := state.applyUnpublishedTestResource(typeurl.Listener, "listener1", listener)

	after, err := c.generateSnapshotFromStateIncrementally(state, before, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, before.GetVersion(envoy_resource.ClusterType), after.GetVersion(envoy_resource.ClusterType))
}

func TestGenerateSnapshotIncrementallyAdvancesGenerationAcrossABA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	c := newCache(logger, WithNodeIDs("node1"))
	policyA := &cilium.NetworkPolicy{EndpointId: 1}
	state := &nodeState{}
	state.seedResource(typeurl.NetworkPolicy, "np1", policyA)

	snapshotA, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)

	changedTypeURLs := state.applyUnpublishedTestResource(typeurl.NetworkPolicy, "np1", &cilium.NetworkPolicy{EndpointId: 2})
	snapshotB, err := c.generateSnapshotFromStateIncrementally(state, snapshotA, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, snapshotA.GetVersion(typeurl.NetworkPolicyURL), snapshotB.GetVersion(typeurl.NetworkPolicyURL))

	changedTypeURLs = state.applyUnpublishedTestResource(typeurl.NetworkPolicy, "np1", policyA)
	snapshotAAgain, err := c.generateSnapshotFromStateIncrementally(state, snapshotB, changedTypeURLs)
	require.NoError(t, err)
	require.NotEqual(t, snapshotA.GetVersion(typeurl.NetworkPolicyURL), snapshotAAgain.GetVersion(typeurl.NetworkPolicyURL),
		"returning to the same contents must not reuse an older on-wire version")
	require.Equal(t, "e0:g2", snapshotAAgain.GetVersion(typeurl.NetworkPolicyURL))
	require.Same(t, policyA, snapshotAAgain.GetResources(typeurl.NetworkPolicyURL)["np1"])
}

func TestCiliumSnapshotIndexedResourcesWithoutDeltaVersions(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	state := &nodeState{}
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	state.seedResource(typeurl.NetworkPolicy, "np1", policy)

	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.Equal(t, policy, snapshot.GetResources(typeurl.NetworkPolicyURL)["np1"])
	require.Empty(t, snapshot.GetVersion("type.googleapis.com/unknown.Resource"))
	require.Nil(t, snapshot.GetResourcesAndTTL("type.googleapis.com/unknown.Resource"))

	require.ErrorContains(t, snapshot.ConstructVersionMap(), "delta xDS is not supported")
	require.Nil(t, snapshot.GetVersionMap(envoy_resource.EndpointType))
	require.Nil(t, snapshot.GetVersionMap(typeurl.NetworkPolicyURL))
	require.Nil(t, snapshot.GetVersionMap("type.googleapis.com/unknown.Resource"))
}

func TestCiliumSnapshotDeltaVersionsTrackResourceChanges(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"), WithDeltaADS()).(*cacheImpl)
	state := &nodeState{epoch: 1, resourceGeneration: 1}
	state.seedResourceAtGeneration(typeurl.NetworkPolicy, "changed", &cilium.NetworkPolicy{EndpointId: 1}, 1)
	state.seedResourceAtGeneration(typeurl.NetworkPolicy, "unchanged", &cilium.NetworkPolicy{EndpointId: 2}, 1)

	initial, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	require.NoError(t, initial.ConstructVersionMap())
	require.Equal(t, map[string]string{
		"changed":   "e1:g1",
		"unchanged": "e1:g1",
	}, initial.GetVersionMap(typeurl.NetworkPolicyURL))

	changedTypeURLs := state.applyUnpublishedTestResource(
		typeurl.NetworkPolicy, "changed", &cilium.NetworkPolicy{EndpointId: 3})
	updated, err := c.generateSnapshotFromStateIncrementally(state, initial, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"changed":   "e1:g2",
		"unchanged": "e1:g1",
	}, updated.GetVersionMap(typeurl.NetworkPolicyURL))

	changedTypeURLs = state.applyUnpublishedTestResource(typeurl.NetworkPolicy, "changed", nil)
	removed, err := c.generateSnapshotFromStateIncrementally(state, updated, changedTypeURLs)
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"unchanged": "e1:g1",
	}, removed.GetVersionMap(typeurl.NetworkPolicyURL))

	rebound := removed.(*ciliumSnapshot).withEpoch(2)
	require.Equal(t, map[string]string{
		"unchanged": "e2:g1",
	}, rebound.GetVersionMap(typeurl.NetworkPolicyURL))
	require.Equal(t, "e1:g1", removed.GetVersionMap(typeurl.NetworkPolicyURL)["unchanged"],
		"rebinding an epoch must not mutate the published snapshot")
}

func TestNativeDeltaResponsesPreserveSnapshotVersions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		subscribed []string
	}{
		{name: "wildcard"},
		{name: "named", subscribed: []string{"changed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			c := newCache(logger, WithNodeIDs("node1"), WithDeltaADS())
			state := &nodeState{epoch: 1, resourceGeneration: 1}
			state.seedResourceAtGeneration(typeurl.NetworkPolicy, "changed", &cilium.NetworkPolicy{EndpointId: 1}, 1)
			state.seedResourceAtGeneration(typeurl.NetworkPolicy, "unchanged", &cilium.NetworkPolicy{EndpointId: 2}, 1)
			initial, err := c.generateSnapshotFromState(state)
			require.NoError(t, err)

			// Bypass Cilium's watch relays so a version-rewriting adapter cannot
			// hide native go-control-plane serialization or comparison errors.
			backend := cache.NewSnapshotCache(true, cache.IDHash{}, snapshotCacheLogger(logger))
			require.NoError(t, backend.SetSnapshot(t.Context(), "node1", initial))
			subscription := stream.NewDeltaSubscription(tc.subscribed, nil, nil, true)
			request := &discovery.DeltaDiscoveryRequest{
				Node:                   &envoy_config_core.Node{Id: "node1"},
				TypeUrl:                typeurl.NetworkPolicyURL,
				ResourceNamesSubscribe: tc.subscribed,
			}
			responses := make(chan cache.DeltaResponse, 1)
			cancel, err := backend.CreateDeltaWatch(request, &subscription, responses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			var response cache.DeltaResponse
			select {
			case response = <-responses:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for initial native Delta response")
			}
			require.IsType(t, &cache.RawDeltaResponse{}, response)
			wire, err := response.GetDeltaDiscoveryResponse()
			require.NoError(t, err)
			if len(tc.subscribed) == 0 {
				require.Len(t, wire.Resources, 2)
			} else {
				require.Len(t, wire.Resources, 1)
			}
			for _, resource := range wire.Resources {
				require.Equal(t, "e1:g1", resource.Version)
				require.Equal(t, response.GetReturnedResources()[resource.Name], resource.Version)
			}

			subscription.SetReturnedResources(response.GetReturnedResources())
			request.ResponseNonce = "acked"
			cancel, err = backend.CreateDeltaWatch(request, &subscription, responses)
			require.NoError(t, err)
			if cancel != nil {
				t.Cleanup(cancel)
			}
			changed := state.applyUnpublishedTestResource(typeurl.NetworkPolicy, "changed", &cilium.NetworkPolicy{EndpointId: 3})
			updated, err := c.generateSnapshotFromStateIncrementally(state, initial, changed)
			require.NoError(t, err)
			require.NoError(t, backend.SetSnapshot(t.Context(), "node1", updated))
			select {
			case response = <-responses:
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for updated native Delta response")
			}
			wire, err = response.GetDeltaDiscoveryResponse()
			require.NoError(t, err)
			require.Len(t, wire.Resources, 1, "unchanged resources must not be resent")
			require.Equal(t, "changed", wire.Resources[0].Name)
			require.Equal(t, "e1:g2", wire.Resources[0].Version)
			require.Equal(t, "e1:g1", updated.GetVersionMap(typeurl.NetworkPolicyURL)["unchanged"])
		})
	}
}

func TestNativeDeltaResponseRetainsHashFallback(t *testing.T) {
	resource := &envoy_config_listener.Listener{Name: "listener"}
	encoded, err := cache.MarshalResource(resource)
	require.NoError(t, err)
	for _, versions := range []map[string]string{nil, {"listener": ""}} {
		response := cache.NewTestRawDeltaResponse(
			&discovery.DeltaDiscoveryRequest{TypeUrl: typeurl.Listener.URL()}, "system-version",
			[]cache_types.ResourceWithTTL{{Resource: resource}}, nil, versions,
		)
		wire, err := response.GetDeltaDiscoveryResponse()
		require.NoError(t, err)
		require.Len(t, wire.Resources, 1)
		require.Equal(t, cache.HashResource(encoded), wire.Resources[0].Version)
	}
}

func TestCreateDeltaWatchSelectsEpochFromInitialResourceVersions(t *testing.T) {
	c := NewCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"), WithDeltaADS()).(*cacheImpl)
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policy, nil, nil))

	request := &discovery.DeltaDiscoveryRequest{
		Node:                    &envoy_config_core.Node{Id: "node1"},
		TypeUrl:                 typeurl.NetworkPolicyURL,
		InitialResourceVersions: map[string]string{"policy": "e1:g99"},
	}
	subscription := stream.NewDeltaSubscription(nil, nil, request.GetInitialResourceVersions(), true)
	responses := make(chan cache.DeltaResponse, 1)
	cancel, err := c.CreateDeltaWatch(request, &subscription, responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	var response cache.DeltaResponse
	select {
	case response = <-responses:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial Delta response")
	}
	require.Equal(t, uint64(2), c.getNodeState("node1").epoch)
	require.Equal(t, uint64(2), c.getNodeState("node1").typeStates[typeurl.NetworkPolicy].negotiatedEpoch)
	require.Equal(t, "e2:g1", response.GetReturnedResources()["policy"])

	deltaResponse, err := response.GetDeltaDiscoveryResponse()
	require.NoError(t, err)
	require.Len(t, deltaResponse.GetResources(), 1)
	require.Equal(t, "policy", deltaResponse.GetResources()[0].GetName())
	require.Equal(t, "e2:g1", deltaResponse.GetResources()[0].GetVersion())
	require.Empty(t, deltaResponse.GetRemovedResources())
	cancel()

	reconnect := &discovery.DeltaDiscoveryRequest{
		Node:                    request.GetNode(),
		TypeUrl:                 typeurl.NetworkPolicyURL,
		InitialResourceVersions: map[string]string{"policy": deltaResponse.GetResources()[0].GetVersion()},
	}
	reconnectedSubscription := stream.NewDeltaSubscription(nil, nil, reconnect.GetInitialResourceVersions(), true)
	reconnectedResponses := make(chan cache.DeltaResponse, 1)
	cancelReconnect, err := c.CreateDeltaWatch(reconnect, &reconnectedSubscription, reconnectedResponses)
	require.NoError(t, err)
	t.Cleanup(cancelReconnect)
	select {
	case response = <-reconnectedResponses:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reconnect Delta response")
	}
	deltaResponse, err = response.GetDeltaDiscoveryResponse()
	require.NoError(t, err)
	require.Empty(t, deltaResponse.GetResources(), "unchanged policy must not be resent")
	require.Empty(t, deltaResponse.GetRemovedResources())
	require.Equal(t, uint64(2), c.getNodeState("node1").epoch)
}

func TestGenerateSnapshotProjectionPreservesDesiredResources(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	state := &nodeState{}
	state.seedResource(typeurl.Listener, "listener", &envoy_config_listener.Listener{Name: "listener"})
	state.seedResource(typeurl.Route, "route", &envoy_config_route.RouteConfiguration{Name: "route"})
	state.seedResource(typeurl.Cluster, "cluster", &envoy_config_cluster.Cluster{
		Name:                 "cluster",
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
	})
	state.seedResource(typeurl.Secret, "secret", &envoy_config_tls.Secret{Name: "secret"})
	state.seedResource(typeurl.NetworkPolicy, "policy", &cilium.NetworkPolicy{EndpointId: 1})
	state.seedResource(typeurl.NetworkPolicyHosts, "hosts", &cilium.NetworkPolicyHosts{Policy: 1})

	snapshot, err := c.generateSnapshotFromState(state)
	require.NoError(t, err)
	for typeURL := range typeurl.Count {
		published := snapshot.GetResourcesAndTTL(typeURL.URL())
		require.Len(t, published, 1, "resource type %s", typeURL.URL())
	}
	// The generated empty CLA belongs only to the snapshot projection, not
	// authoritative desired resource state.
	require.Contains(t, snapshot.GetResourcesAndTTL(envoy_resource.EndpointType), "cluster")
	require.Nil(t, state.getResource(typeurl.Endpoint, "cluster"))

	emptySnapshot, err := c.generateSnapshotFromState(&nodeState{})
	require.NoError(t, err)
	for typeURL := range typeurl.Count {
		require.Nil(t, emptySnapshot.GetResourcesAndTTL(typeURL.URL()))
	}
}

func TestSnapshotDefersResourceEncodingToResponse(t *testing.T) {
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
	const nodeID = "node1"
	// Protobuf binary encoding rejects invalid UTF-8. Generation-based
	// versions let cache mutation and snapshot finalization succeed without
	// encoding the resource; the error belongs to response construction.
	listener := &envoy_config_listener.Listener{Name: "\xff"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, listener.Name, listener, nil, nil))
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(&cache.Request{
		Node: &envoy_config_core.Node{Id: nodeID}, TypeUrl: envoy_resource.ListenerType,
	}, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	_, err = (<-responses).GetDiscoveryResponse()
	require.ErrorContains(t, err, "invalid UTF-8")
}

func TestSnapshotVersions(t *testing.T) {
	for _, tt := range []struct {
		name         string
		epoch        uint64
		generation   callbacks.Generation
		listenerName string
		want         string
	}{
		{"same-generation", 1, 2, "listener", "e1:g2"},
		{"different-generation", 1, 3, "listener", "e1:g3"},
		{"different-epoch", 2, 2, "listener", "e2:g2"},
		{"contents-do-not-define-version", 1, 2, "other", "e1:g2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs("node1"))
			state := &nodeState{epoch: tt.epoch}
			state.seedResourceAtGeneration(typeurl.Listener, tt.listenerName,
				&envoy_config_listener.Listener{Name: tt.listenerName}, tt.generation)
			snapshot, err := c.generateSnapshotFromState(state)
			require.NoError(t, err)
			require.Equal(t, tt.want, snapshot.GetVersion(typeurl.Listener.URL()))
			require.Contains(t, snapshot.GetResources(typeurl.Listener.URL()), tt.listenerName)
			require.Equal(t, formatXDSVersion(tt.epoch, 0), snapshot.GetVersion(typeurl.Secret.URL()))
		})
	}
}

func TestCreateWatchSelectsEpochForNodeAndTypeURL(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	err := c.ApplyResource(t.Context(), "node1", typeurl.NetworkPolicy, "policy", policy, nil, nil)
	require.NoError(t, err)

	request := &cache.Request{
		Node:        &envoy_config_core.Node{Id: "node1"},
		TypeUrl:     typeurl.NetworkPolicyURL,
		VersionInfo: "e1:g99",
	}
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)

	response := <-responses
	require.Equal(t, uint64(2), c.getNodeState("node1").epoch)
	require.Equal(t, uint64(2), c.getNodeState("node1").typeStates[typeurl.NetworkPolicy].negotiatedEpoch)
	require.Equal(t, "e2:g1", response.GetResponseVersion())
	discoveryResponse, err := response.GetDiscoveryResponse()
	require.NoError(t, err)
	require.Len(t, discoveryResponse.GetResources(), 1)
	var returnedPolicy cilium.NetworkPolicy
	require.NoError(t, discoveryResponse.GetResources()[0].UnmarshalTo(&returnedPolicy))
	require.True(t, proto.Equal(policy, &returnedPolicy))
}

func TestCreateWatchRotatesNodeEpochForMixedTypeURLHistory(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	resources := xds.NewResources()
	resources.Clusters["cluster"] = &envoy_config_cluster.Cluster{Name: "cluster"}
	resources.Listeners["listener"] = &envoy_config_listener.Listener{Name: "listener"}
	err := c.ApplyResources(t.Context(), "node1",
		ResourceMutations{Upserted: resources}, nil, NewTypeURLCallbacks())
	require.NoError(t, err)

	createWatch := func(typeURL, version string) cache.Response {
		t.Helper()
		request := &cache.Request{
			Node:        &envoy_config_core.Node{Id: "node1"},
			TypeUrl:     typeURL,
			VersionInfo: version,
		}
		responses := make(chan cache.Response, 1)
		cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
		require.NoError(t, err)
		if cancel != nil {
			t.Cleanup(cancel)
		}
		select {
		case response := <-responses:
			return response
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for xDS response")
			return nil
		}
	}

	// Model a partially updated Envoy left by previous agent instances: CDS
	// still reports epoch 1 while LDS already reports epoch 2. A cache-global
	// choice based on CDS would collide with the retained LDS namespace.
	clusterResponse := createWatch(envoy_resource.ClusterType, "e1:g99")
	require.Equal(t, "e2:g1", clusterResponse.GetResponseVersion())
	beforeRotation := mustSnapshot(t, c, "node1").(*ciliumSnapshot)
	var versionsBeforeRotation typeurl.Slots[string]
	for typeURL := range typeurl.Count {
		versionsBeforeRotation[typeURL] = beforeRotation.GetVersion(typeURL.URL())
	}
	listenerResponse := createWatch(envoy_resource.ListenerType, "e2:g1")
	require.Equal(t, "e3:g1", listenerResponse.GetResponseVersion())

	state := c.getNodeState("node1")
	require.Equal(t, uint64(3), state.epoch)
	require.Equal(t, uint64(3), state.typeStates[typeurl.Cluster].negotiatedEpoch)
	require.Equal(t, uint64(3), state.typeStates[typeurl.Listener].negotiatedEpoch)
	snapshot := mustSnapshot(t, c, "node1")
	require.Equal(t, "e3:g1", snapshot.GetVersion(envoy_resource.ClusterType))
	require.Equal(t, "e3:g1", snapshot.GetVersion(envoy_resource.ListenerType))
	afterRotation := snapshot.(*ciliumSnapshot)
	for typeURL := range typeurl.Count {
		require.Equal(t,
			versionsBeforeRotation[typeURL],
			beforeRotation.GetVersion(typeURL.URL()),
			"epoch rotation mutated the old %s aggregate version", typeURL,
		)
		require.NotEqual(t,
			versionsBeforeRotation[typeURL],
			afterRotation.GetVersion(typeURL.URL()),
			"epoch rotation did not replace the %s aggregate version", typeURL,
		)
		require.Equal(t,
			reflect.ValueOf(beforeRotation.resourceGroups[typeURL].resources.Items).Pointer(),
			reflect.ValueOf(afterRotation.resourceGroups[typeURL].resources.Items).Pointer(),
			"epoch rotation copied %s resources", typeURL,
		)
	}
}

func TestNodeEpochSurvivesStreamGapWithDesiredState(t *testing.T) {
	c := newCache(slog.New(slog.NewTextHandler(os.Stderr, nil)), WithNodeIDs("node1"))
	node := &envoy_config_core.Node{Id: "node1"}
	err := c.ApplyResource(t.Context(), node.GetId(), typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 1}, nil, nil)
	require.NoError(t, err)

	request := &discovery.DiscoveryRequest{
		Node: node, TypeUrl: typeurl.NetworkPolicyURL, VersionInfo: "e1:g99",
	}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 1, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	response := <-responses
	cancel()
	require.Equal(t, "e2:g1", response.GetResponseVersion())
	acknowledgeResponse(t, c, 1, response, "initial")
	c.completionCbs.OnStreamClosed(1, node)

	state := c.getNodeState(node.GetId())
	require.NotNil(t, state, "desired state must retain the negotiated epoch")
	require.True(t, state.streams[callbacks.StreamModeSotW].Empty())
	require.Equal(t, uint64(2), state.epoch)

	request = &discovery.DiscoveryRequest{
		Node: node, TypeUrl: typeurl.NetworkPolicyURL, VersionInfo: "e2:g1",
	}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 2, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
	responses = make(chan cache.Response, 1)
	subscription := stream.NewSotwSubscription(nil, true)
	subscription.SetReturnedResources(response.GetReturnedResources())
	cancel, err = c.CreateWatch(request, subscription, responses)
	require.NoError(t, err)
	cancel()
	require.Equal(t, uint64(2), c.getNodeState(node.GetId()).epoch)
	select {
	case <-responses:
		t.Fatal("a reconnect using the retained epoch unexpectedly received a response")
	default:
	}
	c.completionCbs.OnStreamClosed(2, node)
}

func TestXDSVersionFormatAndEpochParsing(t *testing.T) {
	require.Equal(t, "e1:g2", formatXDSVersion(1, 2))

	for version, expected := range map[string]uint64{
		"e1:g2":        1,
		"e42:anything": 42,
	} {
		epoch, ok := parseXDSEpoch(version)
		require.True(t, ok, version)
		require.Equal(t, expected, epoch, version)
	}
	for _, version := range []string{"", "e0:g1", "e:g1", "e-1:g1", "1:g1", "legacy-hash"} {
		_, ok := parseXDSEpoch(version)
		require.False(t, ok, version)
	}
}

func TestSelectEpochDiffersFromReportedEpoch(t *testing.T) {
	for _, test := range []struct {
		version string
		epoch   uint64
	}{
		{version: "", epoch: 1},
		{version: "legacy-hash", epoch: 1},
		{version: "e1:g100", epoch: 2},
		{version: "e3:g9", epoch: 1},
	} {
		t.Run(test.version, func(t *testing.T) {
			state := &nodeState{}
			require.NoError(t, state.selectEpochLocked(typeurl.Listener, singleVersion(test.version)))
			require.Equal(t, test.epoch, state.epoch)
			state.commitEpochNegotiation(typeurl.Listener)

			// A later stream cannot change the same node and TypeURL epoch.
			require.NoError(t, state.selectEpochLocked(typeurl.Listener, singleVersion("e2:g7")))
			require.Equal(t, test.epoch, state.epoch)
		})
	}
}

// setTestNodeEpochs avoids treating test-local version echoes as an old agent.
func (c *cacheImpl) setTestNodeEpochs(nodeID string, epoch uint64) {
	state := c.getNodeState(nodeID)
	state.epoch = epoch
	for typeURL := range typeurl.Count {
		state.typeStates[typeURL].negotiatedEpoch = epoch
	}
}

func TestEmptyKnownNodePreservesEpochAcrossStreamGap(t *testing.T) {
	const nodeID = "node1"
	c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
	node := &envoy_config_core.Node{Id: nodeID}
	request := &discovery.DiscoveryRequest{Node: node, TypeUrl: typeurl.NetworkPolicyURL}
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 1, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(1, request))
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	initial := <-responses
	cancel()
	state := c.getNodeState(nodeID)
	require.Equal(t, "e1:g0", initial.GetResponseVersion())
	require.True(t, state.streams[callbacks.StreamModeSotW].Has(1))
	c.completionCbs.OnStreamClosed(1, node)
	require.Same(t, state, c.getNodeState(nodeID), "known nodes persist even with empty desired state")
	require.True(t, state.streams[callbacks.StreamModeSotW].Empty())
	require.Equal(t, uint64(1), state.epoch)
	request.VersionInfo = initial.GetResponseVersion()
	require.NoError(t, c.completionCbs.OnStreamOpen(t.Context(), 2, ""))
	require.NoError(t, c.completionCbs.OnStreamRequest(2, request))
	cancel, err = c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	select {
	case <-responses:
		t.Fatal("reconnect must retain the negotiated epoch without inventing an update")
	default:
	}
	c.completionCbs.OnStreamClosed(2, node)
}
