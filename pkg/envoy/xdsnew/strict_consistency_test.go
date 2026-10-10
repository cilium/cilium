// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func TestStrictADSRejectsTransactionsWithoutDebugCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typeURL  typeurl.Index
		resource proto.Message
		upserted xds.Resources
	}{
		{"orphan-route", typeurl.Route, &route.RouteConfiguration{Name: "orphan"},
			xds.Resources{Routes: map[string]*route.RouteConfiguration{"orphan": {Name: "orphan"}}}},
		{"missing-route", typeurl.Listener, strictTestListener(t, "orphan", "missing"),
			xds.Resources{Listeners: map[string]*listener.Listener{"orphan": strictTestListener(t, "orphan", "missing")}}},
		{"orphan-endpoint", typeurl.Endpoint, &endpoint.ClusterLoadAssignment{ClusterName: "orphan"},
			xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{"orphan": {ClusterName: "orphan"}}}},
		// This suffix has no special cache semantics. It must not bypass the
		// incremental check now that snapshot generation no longer filters it.
		{"orphan-endpoint-colon-asterisk", typeurl.Endpoint, &endpoint.ClusterLoadAssignment{ClusterName: "orphan:*"},
			xds.Resources{Endpoints: map[string]*endpoint.ClusterLoadAssignment{"orphan:*": {ClusterName: "orphan:*"}}}},
	} {
		for _, api := range []string{"single", "bulk"} {
			t.Run(tc.name+"/"+api, func(t *testing.T) {
				const nodeID = "node1"
				observer := &testNPDSListenerObserver{nodeID: nodeID, matches: func(l *listener.Listener) bool { return l != nil }}
				c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelInfo)), true,
					WithNodeIDs(nodeID), WithListenerObserver(observer)).(*cacheImpl)
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancel)
				wg := completion.NewWaitGroup(ctx)
				t.Cleanup(wg.Cancel)
				callbackCalls := 0
				callback := func(error) { callbackCalls++ }
				var rollback Rollback
				var err error
				name := cache.GetResourceName(tc.resource)
				if api == "single" {
					rollback, err = c.ApplyResourceWithRollback(ctx, nodeID, tc.typeURL, name, tc.resource, wg, callback)
				} else {
					var waits TypeURLCallbacks
					waits.Set(tc.typeURL, callback)
					rollback, err = c.ApplyResourcesWithRollback(ctx, nodeID, ResourceMutations{Upserted: tc.upserted}, wg, waits)
				}
				require.ErrorContains(t, err, "strict ADS cache mutation is inconsistent")
				require.Nil(t, rollback)
				require.True(t, c.HasNode(nodeID), "rejection must preserve the known node")
				require.Nil(t, c.GetResource(nodeID, tc.typeURL, name))
				_, err = c.GetSnapshot(nodeID)
				require.Error(t, err, "rejection must precede snapshot installation")
				require.NoError(t, wg.Wait(), "a rejected update must not register an ACK wait")
				require.Zero(t, callbackCalls)
				require.Zero(t, observer.count, "an uncommitted listener must not affect the observer")
				c.getNodeState(nodeID).requireNoRollbackOwners(t)
				c.getNodeState(nodeID).requireNoUnsentRollbacks(t)
			})
		}
	}
}

func TestStrictADSRejectsReferencedRouteRemoval(t *testing.T) {
	for _, api := range []string{"single", "bulk"} {
		for _, typedNil := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typed-nil=%t", api, typedNil), func(t *testing.T) {
				const nodeID = "node1"
				c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs(nodeID))
				initialRoute := &route.RouteConfiguration{Name: "r1"}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Listeners: map[string]*listener.Listener{"l1": strictTestListener(t, "l1", "r1")},
					Routes:    map[string]*route.RouteConfiguration{"r1": initialRoute},
				}}, nil, TypeURLCallbacks{}))
				var rollback Rollback
				var err error
				if api == "single" {
					var resource proto.Message
					if typedNil {
						resource = (*route.RouteConfiguration)(nil)
					}
					rollback, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Route, "r1", resource, nil, nil)
				} else {
					mutations := ResourceMutations{Removed: xds.Resources{Routes: map[string]*route.RouteConfiguration{"r1": nil}}}
					if typedNil {
						mutations = ResourceMutations{Upserted: mutations.Removed}
					}
					rollback, err = c.ApplyResourcesWithRollback(t.Context(), nodeID, mutations, nil, TypeURLCallbacks{})
				}
				require.ErrorContains(t, err, "missing RDS resource")
				require.Nil(t, rollback)
				current := c.GetResource(nodeID, typeurl.Route, "r1")
				require.NotNil(t, current)
				require.Same(t, initialRoute, current)
			})
		}
	}
}

func TestStrictADSParentReferenceChanges(t *testing.T) {
	for _, parentType := range []typeurl.Index{typeurl.Listener, typeurl.Cluster} {
		t.Run(parentType.URL(), func(t *testing.T) {
			const nodeID = "node1"
			c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs(nodeID)).(*cacheImpl)
			var initial, replacement ResourceMutations
			var orphan proto.Message
			var childType typeurl.Index
			if parentType == typeurl.Listener {
				childType = typeurl.Route
				initial.Upserted = xds.Resources{Listeners: map[string]*listener.Listener{"parent": strictTestListener(t, "parent", "old")},
					Routes: map[string]*route.RouteConfiguration{"old": {Name: "old"}}}
				replacement = ResourceMutations{Removed: xds.Resources{Routes: initial.Upserted.Routes}, Upserted: xds.Resources{
					Listeners: map[string]*listener.Listener{"parent": strictTestListener(t, "parent", "new")},
					Routes:    map[string]*route.RouteConfiguration{"new": {Name: "new"}},
				}}
				orphan = &route.RouteConfiguration{Name: "old"}
			} else {
				childType = typeurl.Endpoint
				initial.Upserted = xds.Resources{Clusters: map[string]*cluster.Cluster{"parent": strictTestEDSCluster("parent", "old")},
					Endpoints: map[string]*endpoint.ClusterLoadAssignment{"old": {ClusterName: "old"}}}
				replacement = ResourceMutations{Removed: xds.Resources{Endpoints: initial.Upserted.Endpoints}, Upserted: xds.Resources{
					Clusters:  map[string]*cluster.Cluster{"parent": strictTestEDSCluster("parent", "new")},
					Endpoints: map[string]*endpoint.ClusterLoadAssignment{"new": {ClusterName: "new"}},
				}}
				orphan = &endpoint.ClusterLoadAssignment{ClusterName: "old"}
			}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, initial, nil, TypeURLCallbacks{}))
			// Retargeting alone must not strand the explicit old child. The same
			// mutation succeeds when the old child is removed and the new one added.
			var updated proto.Message = replacement.Upserted.Listeners["parent"]
			if parentType == typeurl.Cluster {
				updated = replacement.Upserted.Clusters["parent"]
			}
			require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, parentType, "parent", updated, nil, nil), "inconsistent")
			rollback, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, replacement, nil, TypeURLCallbacks{})
			require.NoError(t, err)
			require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, nodeID, parentType)))
			require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, childType, "old", orphan, nil, nil), "orphan")
			// A successful caller revert must restore the reference index as well
			// as the protobufs: the now-unreferenced new child must be rejected.
			require.NoError(t, rollback.Revert())
			require.Nil(t, c.GetResource(nodeID, childType, "new"))
			var newChild proto.Message = replacement.Upserted.Routes["new"]
			if childType == typeurl.Endpoint {
				newChild = replacement.Upserted.Endpoints["new"]
			}
			require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, childType, "new", newChild, nil, nil), "orphan")
			require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, nodeID, parentType)))
			require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, parentType, "parent", nil, nil, nil), "orphan")
		})
	}
}

func TestStrictADSListenerReferenceForms(t *testing.T) {
	for _, form := range []string{"default-chain", "duplicate-reference", "scoped-routes", "multiple-scoped-routes"} {
		t.Run(form, func(t *testing.T) {
			const nodeID = "node1"
			c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs(nodeID)).(*cacheImpl)
			parent := strictTestListener(t, "parent", "child")
			switch form {
			case "default-chain":
				parent.DefaultFilterChain, parent.FilterChains = parent.FilterChains[0], nil
			case "duplicate-reference":
				parent.DefaultFilterChain = parent.FilterChains[0]
				parent.FilterChains = append(parent.FilterChains, parent.FilterChains[0])
			case "scoped-routes", "multiple-scoped-routes":
				secondRoute := "child"
				if form == "multiple-scoped-routes" {
					secondRoute = "child2"
				}
				parent.FilterChains[0].Filters[0].ConfigType = &listener.Filter_TypedConfig{TypedConfig: mustAny(t,
					&http.HttpConnectionManager{RouteSpecifier: &http.HttpConnectionManager_ScopedRoutes{
						ScopedRoutes: &http.ScopedRoutes{ConfigSpecifier: &http.ScopedRoutes_ScopedRouteConfigurationsList{
							ScopedRouteConfigurationsList: &http.ScopedRouteConfigurationsList{ScopedRouteConfigurations: []*route.ScopedRouteConfiguration{
								{Name: "scope1", RouteConfigurationName: "child"}, {Name: "scope2", RouteConfigurationName: secondRoute},
							}},
						}},
					}})}
			}
			// Use the independent full-check extractor to form the expected child
			// set, then verify acceptance and removal through the mutation APIs.
			upstream := cache.GetResourceReferences(map[string]cache_types.ResourceWithTTL{"parent": {Resource: parent}})[envoy_resource.RouteType]
			routes := make(map[string]*route.RouteConfiguration, len(upstream))
			for name := range upstream {
				routes[name] = &route.RouteConfiguration{Name: name}
			}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*listener.Listener{"parent": parent}, Routes: routes,
			}}, nil, TypeURLCallbacks{}))
			require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, typeurl.Route, "child", nil, nil, nil), "missing RDS")
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: xds.Resources{
				Listeners: map[string]*listener.Listener{"parent": nil}, Routes: routes,
			}}, nil, TypeURLCallbacks{}))
			require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, nodeID, typeurl.Listener)))
		})
	}
}

func TestStrictADSClusterReferenceForms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cluster *cluster.Cluster
	}{
		{"service-name", strictTestEDSCluster("parent", "child")},
		{"cluster-name", strictTestEDSCluster("parent", "")},
		{"static-cluster", &cluster.Cluster{Name: "parent"}},
		{"custom-cluster", &cluster.Cluster{Name: "parent", ClusterDiscoveryType: &cluster.Cluster_ClusterType{
			ClusterType: &cluster.Cluster_CustomClusterType{Name: "custom"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := cache.GetResourceReferences(map[string]cache_types.ResourceWithTTL{
				"parent": {Resource: tc.cluster},
			})[envoy_resource.EndpointType]
			c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs("node1")).(*cacheImpl)
			require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Cluster, "parent", tc.cluster, nil, nil))
			for name := range upstream {
				require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Endpoint, name, &endpoint.ClusterLoadAssignment{ClusterName: name}, nil, nil))
				require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Endpoint, name, nil, nil, nil),
					"removing an explicit assignment restores its synthesized empty CLA")
			}
			require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, "node1", typeurl.Cluster)))
			require.NoError(t, c.ApplyResource(t.Context(), "node1", typeurl.Cluster, "parent", nil, nil, nil))
			require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, "node1", typeurl.Cluster)))
		})
	}
}

func TestStrictADSRejectionCleansPreviouslyRegisteredUnchangedWait(t *testing.T) {
	const nodeID = "node1"
	c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs(nodeID)).(*cacheImpl)
	secret := &tls.Secret{Name: "secret"}
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Secret, secret.Name, secret, nil, nil))
	snapshot := requestSnapshotForTest(t, c, nodeID, typeurl.Cluster)
	secretRollback := c.getNodeState(nodeID).typeStates[typeurl.Secret].rollbacks.unsent
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	var callbackErr error
	var waits TypeURLCallbacks
	waits.Set(typeurl.Secret, func(err error) { callbackErr = err })
	rollback, err := c.ApplyResourcesWithRollback(ctx, nodeID, ResourceMutations{Upserted: xds.Resources{
		Secrets: map[string]*tls.Secret{secret.Name: secret},
		Routes:  map[string]*route.RouteConfiguration{"orphan": {Name: "orphan"}},
	}}, wg, waits)
	require.ErrorContains(t, err, "orphan RDS")
	require.Nil(t, rollback)
	require.ErrorIs(t, wg.Wait(), err)
	require.ErrorIs(t, callbackErr, err)
	require.Same(t, snapshot, mustSnapshot(t, c, nodeID))
	require.Empty(t, maps.Collect(c.Routes(nodeID)))
	c.getNodeState(nodeID).requireNoRollbackOwners(t)
	require.Nil(t, c.getNodeState(nodeID).typeStates[typeurl.Route].rollbacks.unsent)
	require.Same(t, secretRollback, c.getNodeState(nodeID).typeStates[typeurl.Secret].rollbacks.unsent,
		"rejection must not consume the independent pending Secret rollback")
}

func TestStrictADSReferenceIndexRestoredAfterPublicationFailure(t *testing.T) {
	for _, parentType := range []typeurl.Index{typeurl.Listener, typeurl.Cluster} {
		for _, mutation := range []string{"add-reference", "retarget"} {
			t.Run(parentType.URL()+"/"+mutation, func(t *testing.T) {
				const nodeID = "node1"
				mock := newMockSnapshotCache()
				c := newInitializedTestCache(mock)
				c.strictAdsMode = true
				c.logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				parentName, childName := "second", "old"
				if mutation == "retarget" {
					parentName, childName = "parent", "new"
				}
				var initial xds.Resources
				var proposed ResourceMutations
				var childType typeurl.Index
				var newChild proto.Message
				if parentType == typeurl.Listener {
					childType = typeurl.Route
					initial = xds.Resources{Listeners: map[string]*listener.Listener{"parent": strictTestListener(t, "parent", "old")},
						Routes: map[string]*route.RouteConfiguration{"old": {Name: "old"}}}
					proposed.Upserted.Listeners = map[string]*listener.Listener{parentName: strictTestListener(t, parentName, childName)}
					newChild = &route.RouteConfiguration{Name: "new"}
					if mutation == "retarget" {
						proposed.Removed.Routes = initial.Routes
						proposed.Upserted.Routes = map[string]*route.RouteConfiguration{"new": newChild.(*route.RouteConfiguration)}
					}
				} else {
					childType = typeurl.Endpoint
					initial = xds.Resources{Clusters: map[string]*cluster.Cluster{"parent": strictTestEDSCluster("parent", "old")},
						Endpoints: map[string]*endpoint.ClusterLoadAssignment{"old": {ClusterName: "old"}}}
					proposed.Upserted.Clusters = map[string]*cluster.Cluster{parentName: strictTestEDSCluster(parentName, childName)}
					newChild = &endpoint.ClusterLoadAssignment{ClusterName: "new"}
					if mutation == "retarget" {
						proposed.Removed.Endpoints = initial.Endpoints
						proposed.Upserted.Endpoints = map[string]*endpoint.ClusterLoadAssignment{"new": newChild.(*endpoint.ClusterLoadAssignment)}
					}
				}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: initial}, nil, TypeURLCallbacks{}))
				// Publication failure is synchronous only while the directly
				// affected parent has an open watch. The mock leaves it open.
				cancelWatch, watchErr := c.CreateWatch(&cache.Request{
					Node: &core.Node{Id: nodeID}, TypeUrl: parentType.URL(),
				}, stream.NewSotwSubscription(nil, true), make(chan cache.Response, 1))
				require.NoError(t, watchErr)
				t.Cleanup(cancelWatch)
				snapshot := mustSnapshot(t, c, nodeID)
				parent := c.GetResource(nodeID, parentType, "parent")
				mock.setSnapshotErr = errors.New("publication failed")
				rollback, err := c.ApplyResourcesWithRollback(t.Context(), nodeID, proposed, nil, TypeURLCallbacks{})
				require.ErrorIs(t, err, mock.setSnapshotErr)
				require.Nil(t, rollback)
				mock.setSnapshotErr = nil
				require.Same(t, snapshot, mustSnapshot(t, c, nodeID))
				current := c.GetResource(nodeID, parentType, "parent")
				require.NotNil(t, current)
				require.Same(t, parent, current)
				require.Nil(t, c.GetResource(nodeID, childType, "new"))
				// Neither added references nor decremented old counts may survive
				// failure. Verify this through subsequent API transactions, not by
				// asserting the internal index layout.
				require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, parentType, "parent", nil, nil, nil), "orphan")
				require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, childType, "new", newChild, nil, nil), "orphan")
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: initial}, nil, TypeURLCallbacks{}))
				require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, nodeID, typeurl.Cluster)))
			})
		}
	}
}

func TestStrictADSNACKBatchRestoresReferenceIndex(t *testing.T) {
	for _, parentType := range []typeurl.Index{typeurl.Listener, typeurl.Cluster} {
		for _, failPublication := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/publication-failure=%t", parentType.URL(), failPublication), func(t *testing.T) {
				const nodeID = "coverage-node"
				c := NewCache(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)), true, WithNodeIDs(nodeID)).(*cacheImpl)
				t.Cleanup(func() {
					for id := range int64(3) {
						c.completionCbs.OnStreamClosed(id+1, nil)
					}
				})
				pair := func(childName string) xds.Resources {
					if parentType == typeurl.Listener {
						return xds.Resources{
							Listeners: map[string]*listener.Listener{"parent": strictTestListener(t, "parent", childName)},
							Routes:    map[string]*route.RouteConfiguration{childName: {Name: childName}},
						}
					}
					return xds.Resources{
						Clusters:  map[string]*cluster.Cluster{"parent": strictTestEDSCluster("parent", childName)},
						Endpoints: map[string]*endpoint.ClusterLoadAssignment{childName: {ClusterName: childName}},
					}
				}
				baseline, a, b := pair("baseline"), pair("a"), pair("b")
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: baseline}, nil, TypeURLCallbacks{}))
				baselineParent := c.GetResource(nodeID, parentType, "parent")
				acceptPublishedSnapshotVersions(t, c, 1, &core.Node{Id: nodeID}, requestSnapshotForTest(t, c, nodeID, parentType))
				first := coverageStream{cache: c, id: 1, typeURL: parentType.URL()}
				second := coverageStream{cache: c, id: 2, typeURL: parentType.URL()}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: baseline, Upserted: a}, nil, TypeURLCallbacks{}))
				first.receive(t, "parent")
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: a, Upserted: b}, nil, TypeURLCallbacks{}))
				response := second.receive(t, "parent")
				currentParent := c.GetResource(nodeID, parentType, "parent")
				before := c.getNodeState(nodeID).resourceGeneration
				if failPublication {
					backend := c.SnapshotCache
					failed := newMockSnapshotCache()
					failed.snapshots[nodeID] = mustSnapshot(t, c, nodeID)
					failure := errors.New("corrective publication failed")
					failed.setSnapshotErr = failure
					c.SnapshotCache = failed
					// An open watch makes corrective publication synchronous;
					// without it, recovery commits only desired state.
					cancelWatch, err := c.CreateWatch(&cache.Request{
						Node: &core.Node{Id: nodeID}, TypeUrl: parentType.URL(),
						ResourceNames: []string{"parent"}, VersionInfo: response.VersionInfo,
					}, second.sub, make(chan cache.Response, 1))
					require.NoError(t, err)
					t.Cleanup(cancelWatch)
					require.ErrorIs(t, c.completionCbs.OnStreamRequest(second.id, &discovery.DiscoveryRequest{
						TypeUrl: parentType.URL(), ResponseNonce: response.Nonce, ResourceNames: []string{"parent"},
						ErrorDetail: &status.Status{Message: "rejected parent"},
					}), failure)
					require.Equal(t, before, c.getNodeState(nodeID).resourceGeneration)
					require.Same(t, currentParent, c.GetResource(nodeID, parentType, "parent"))
					c.SnapshotCache = backend
					c.completionCbs.OnStreamClosed(second.id, nil)
					second = coverageStream{cache: c, id: 3, typeURL: parentType.URL()}
					response = second.receive(t, "parent")
				}
				// Failed attempts reserve a generation without advancing desired
				// state. The successful batch reserves only one further generation.
				beforeCorrection := c.resourceGeneration
				second.reply(t, response, "rejected parent", "parent")
				require.Equal(t, beforeCorrection+1, c.getNodeState(nodeID).resourceGeneration, "one final correction for both inverses")
				require.Same(t, baselineParent, c.GetResource(nodeID, parentType, "parent"))
				require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, nodeID, parentType)))
				// Only the baseline reference may survive. If either the failed
				// correction or intermediate inverse left counts behind, these
				// unreferenced children could be accepted, or removal could fail.
				childType := typeurl.Route
				if parentType == typeurl.Cluster {
					childType = typeurl.Endpoint
				}
				for _, childName := range []string{"a", "b"} {
					var child proto.Message = &route.RouteConfiguration{Name: childName}
					if childType == typeurl.Endpoint {
						child = &endpoint.ClusterLoadAssignment{ClusterName: childName}
					}
					require.ErrorContains(t, c.ApplyResource(t.Context(), nodeID, childType, childName,
						child, nil, nil), "orphan")
				}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Removed: baseline}, nil, TypeURLCallbacks{}))
				require.NoError(t, CheckSnapshotConsistency(requestSnapshotForTest(t, c, nodeID, parentType)))
			})
		}
	}
}
