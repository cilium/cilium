// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

func TestFailedCoalescedABAPublicationKeepsPendingPublication(t *testing.T) {
	c := newCoverageCache(t)
	policy := &cilium.NetworkPolicy{EndpointId: 1}
	require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policy, nil, nil))
	s := coverageStream{cache: c, id: 1, typeURL: NetworkPolicyTypeURL}
	s.reply(t, s.receive(t), "")
	baseline := mustSnapshot(t, c, "coverage-node")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	wg := completion.NewWaitGroup(ctx)
	t.Cleanup(wg.Cancel)
	done := make(chan error, 1)
	require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy",
		&cilium.NetworkPolicy{EndpointId: 2}, wg, func(err error) { done <- err }))
	require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.NetworkPolicy, "policy", policy, nil, nil))
	failed := newMockSnapshotCache()
	failed.snapshots["coverage-node"] = baseline
	failed.setSnapshotErr = errors.New("publication failed before installation")
	original := c.SnapshotCache
	c.SnapshotCache = failed
	request := &cache.Request{Node: &core.Node{Id: "coverage-node"}, TypeUrl: NetworkPolicyTypeURL, VersionInfo: s.version}
	cancelWatch, err := c.CreateWatch(request, s.sub, make(chan cache.Response, 1))
	require.ErrorIs(t, err, failed.setSnapshotErr,
		"a failed installation must preserve the earlier published snapshot")
	require.Nil(t, cancelWatch)
	require.Same(t, baseline, mustSnapshot(t, c, "coverage-node"))
	requireCoveragePending(t, done)
	c.SnapshotCache = original
	responses := make(chan cache.Response, 1)
	cancelWatch, err = c.CreateWatch(request, s.sub, responses)
	require.NoError(t, err)
	t.Cleanup(cancelWatch)
	// A-B-A retains identical contents but advances the generation version.
	// Finalization must publish the preserved desired state and wait for its new ACK.
	retried := mustSnapshot(t, c, "coverage-node")
	require.NotSame(t, baseline, retried, "retry must publish the preserved desired state")
	require.NotEqual(t, baseline.GetVersion(NetworkPolicyTypeURL), retried.GetVersion(NetworkPolicyTypeURL))
	requireCoveragePending(t, done)
	s.reply(t, s.deliver(t, <-responses), "")
	require.NoError(t, wg.Wait())
	require.NoError(t, <-done, "successful A-B-A publication must resolve its wait on ACK")
}

func TestNoOpWaitWithoutPublishedBaseline(t *testing.T) {
	for _, cleared := range []bool{false, true} {
		for _, bulk := range []bool{false, true} {
			for _, rejection := range []string{"", "listener response rejected"} {
				t.Run(fmt.Sprintf("cleared=%t/bulk=%t/nack=%t", cleared, bulk, rejection != ""), func(t *testing.T) {
					c := newCoverageCache(t)
					policy := &cilium.NetworkPolicy{EndpointId: 1}
					require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.NetworkPolicy, "policy", policy, nil, nil))
					if cleared {
						requestSnapshotForTest(t, c, "coverage-node", typeurl.NetworkPolicy)
						c.ClearSnapshot("coverage-node")
					}
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					t.Cleanup(cancel)
					wg := completion.NewWaitGroup(ctx)
					t.Cleanup(wg.Cancel)
					done := make(chan error, 1)
					callback := func(err error) { done <- err }
					if bulk {
						var waits TypeURLCallbacks
						waits.Set(typeurl.Listener, callback)
						require.NoError(t, c.ApplyResources(ctx, "coverage-node", ResourceMutations{Removed: xds.Resources{
							Listeners: map[string]*listener.Listener{"absent": nil},
						}}, wg, waits))
					} else {
						require.NoError(t, c.ApplyResource(ctx, "coverage-node", typeurl.Listener, "absent", nil, wg, callback))
					}
					requireCoveragePending(t, done)
					_, err := c.GetSnapshot("coverage-node")
					require.Error(t, err, "a no-op must not force publication")
					s := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
					response := s.receive(t)
					require.Empty(t, response.Resources)
					s.reply(t, response, rejection)
					if rejection == "" {
						require.NoError(t, wg.Wait())
						require.NoError(t, <-done)
					} else {
						require.ErrorContains(t, wg.Wait(), rejection)
						require.ErrorContains(t, <-done, rejection)
					}
					require.Empty(t, done)
					current := c.GetResource("coverage-node", typeurl.NetworkPolicy, "policy")
					require.NotNil(t, current)
					require.Same(t, policy, current, "an empty LDS outcome must not revert the unrelated policy")
				})
			}
		}
	}
}

func TestEpochRotationPreservesUnrelatedUnpublishedChanges(t *testing.T) {
	for _, failPublication := range []bool{false, true} {
		t.Run(fmt.Sprintf("publication-failure=%t", failPublication), func(t *testing.T) {
			c := newCoverageCache(t)
			const nodeID = "coverage-node"
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster",
				&cluster.Cluster{Name: "cluster"}, nil, nil))
			cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL(), version: "e1:g99"}
			cds.reply(t, cds.receive(t), "")
			baseline := mustSnapshot(t, c, nodeID)
			require.Equal(t, "e2:g1", baseline.GetVersion(typeurl.Cluster.URL()))

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			t.Cleanup(cancel)
			wg := completion.NewWaitGroup(ctx)
			t.Cleanup(wg.Cancel)
			done := make(chan error, 1)
			policy := &cilium.NetworkPolicy{EndpointId: 1}
			require.NoError(t, c.ApplyResource(ctx, nodeID, typeurl.NetworkPolicy, "policy", policy, wg, func(err error) { done <- err }))
			request := &cache.Request{Node: &core.Node{Id: nodeID}, TypeUrl: typeurl.Listener.URL(), VersionInfo: "e2:g0"}
			sub := stream.NewSotwSubscription(nil, true)
			responses := make(chan cache.Response, 1)
			if failPublication {
				original := c.SnapshotCache
				failed := newMockSnapshotCache()
				failed.snapshots[nodeID] = baseline
				failed.setSnapshotErr = errors.New("epoch publication failed")
				c.SnapshotCache = failed
				cancel, err := c.CreateWatch(request, sub, responses)
				require.ErrorIs(t, err, failed.setSnapshotErr)
				require.Nil(t, cancel)
				require.Same(t, baseline, mustSnapshot(t, c, nodeID))
				c.SnapshotCache = original
			}
			cancelWatch, err := c.CreateWatch(request, sub, responses)
			require.NoError(t, err)
			t.Cleanup(cancelWatch)
			lds := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL(), sub: sub}
			lds.reply(t, lds.deliver(t, <-responses), "")
			rotated := mustSnapshot(t, c, nodeID)
			require.Equal(t, "e3:g1", rotated.GetVersion(typeurl.Cluster.URL()))
			require.Empty(t, rotated.GetResources(NetworkPolicyTypeURL), "rotation must not publish the pending policy")
			require.Equal(t, "e2:g1", baseline.GetVersion(typeurl.Cluster.URL()), "the earlier snapshot stays immutable")
			requireCoveragePending(t, done)
			current := c.GetResource(nodeID, typeurl.NetworkPolicy, "policy")
			require.NotNil(t, current)
			require.Same(t, policy, current)
			npds := coverageStream{cache: c, id: 1, typeURL: NetworkPolicyTypeURL}
			npds.reply(t, npds.receive(t), "")
			require.NoError(t, wg.Wait())
			require.NoError(t, <-done)
		})
	}
}

func TestEpochExhaustionDoesNotCorruptKnownNode(t *testing.T) {
	c := newCoverageCache(t)
	cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL(), version: fmt.Sprintf("e%d:g99", ^uint64(0))}
	cds.reply(t, cds.receive(t), "")
	baseline := mustSnapshot(t, c, "coverage-node")
	request := &cache.Request{Node: &core.Node{Id: "coverage-node"}, TypeUrl: typeurl.Listener.URL(), VersionInfo: "e1:g0"}
	responses := make(chan cache.Response, 1)
	cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.ErrorContains(t, err, "epoch space exhausted")
	require.Nil(t, cancel)
	require.Empty(t, responses)
	require.Same(t, baseline, mustSnapshot(t, c, "coverage-node"))

	// A failing request does not commit negotiation. A non-conflicting retry
	// still uses the positive epoch selected for this known node.
	request.VersionInfo = "e2:g0"
	cancel, err = c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
	require.NoError(t, err)
	t.Cleanup(cancel)
	require.Equal(t, "e1:g0", (<-responses).GetResponseVersion())
}

func TestClusterAddsMissingCLAAnswersExistingEDSWatch(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, existingCluster := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict=%t/existing-cluster=%t", strict, existingCluster), func(t *testing.T) {
				logger := slog.New(slog.DiscardHandler)
				if strict {
					logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				}
				const nodeID = "coverage-node"
				c := NewCache(logger, strict, WithNodeIDs(nodeID)).(*cacheImpl)
				t.Cleanup(func() {
					c.completionCbs.OnStreamClosed(1, nil)
					c.completionCbs.OnStreamClosed(2, nil)
				})
				if existingCluster {
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster",
						&cluster.Cluster{Name: "cluster"}, nil, nil))
				}

				// Subscribe before a Cluster refers to this EDS name. The empty
				// response establishes a version, but no assignment was delivered.
				eds := coverageStream{cache: c, id: 1, typeURL: typeurl.Endpoint.URL()}
				empty := eds.receive(t, "backend")
				require.Empty(t, empty.Resources)
				eds.reply(t, empty, "", "backend")
				cds := coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
				cds.reply(t, cds.receive(t), "")

				openWatch := func(s *coverageStream, names ...string) chan cache.Response {
					request := &cache.Request{
						Node: &core.Node{Id: nodeID}, TypeUrl: s.resourceType(),
						VersionInfo: s.version, ResourceNames: names,
					}
					require.NoError(t, c.completionCbs.OnStreamRequest(s.id, request))
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(request, s.sub, responses)
					require.NoError(t, err)
					t.Cleanup(cancel)
					require.Empty(t, responses, "the acknowledged version must establish an open watch")
					return responses
				}
				edsResponses := openWatch(&eds, "backend")
				cdsResponses := openWatch(&cds)

				// The CDS watch lets finalization run. The new EDS reference adds
				// a synthesized CLA only to the snapshot, not to desired cache state.
				// No new EDS request follows: publication must answer the existing
				// watch even though no Cluster previously subscribed to this name.
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "cluster",
					strictTestEDSCluster("cluster", "backend"), nil, nil))
				require.Nil(t, c.GetResource(nodeID, typeurl.Endpoint, "backend"))
				require.Contains(t, mustSnapshot(t, c, nodeID).GetResources(typeurl.Endpoint.URL()), "backend")
				require.Len(t, cdsResponses, 1, "the Cluster update must have been published")
				// Buffered handoffs finish synchronously before ApplyResource returns;
				// assert delivery before reading so a regression fails without hanging.
				require.Len(t, edsResponses, 1, "the changed EDS projection must answer the already-open watch")
				response := eds.deliver(t, <-edsResponses)
				require.NotEqual(t, empty.VersionInfo, response.VersionInfo,
					"a new synthesized assignment needs a new EDS wire version")
				require.Len(t, response.Resources, 1)
				var assignment endpoint.ClusterLoadAssignment
				require.NoError(t, response.Resources[0].UnmarshalTo(&assignment))
				require.Equal(t, "backend", assignment.ClusterName)
				require.Empty(t, assignment.Endpoints)
				eds.reply(t, response, "", "backend")
				cds.reply(t, cds.deliver(t, <-cdsResponses), "")
			})
		}
	}
}

func TestIncrementalCLAProjection(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, mode := range []string{"remove-one-reference", "remove-last-reference", "retarget-one-reference", "replace-explicit", "remove-explicit"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, mode), func(t *testing.T) {
				logger := slog.New(slog.DiscardHandler)
				if strict {
					logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
				}
				c := NewCache(logger, strict, WithNodeIDs("node1")).(*cacheImpl)
				initial := xds.Resources{Clusters: map[string]*cluster.Cluster{
					"a": strictTestEDSCluster("a", "shared"), "b": strictTestEDSCluster("b", "shared"),
				}}
				var explicit *endpoint.ClusterLoadAssignment
				if mode == "replace-explicit" || mode == "remove-explicit" {
					explicit = &endpoint.ClusterLoadAssignment{ClusterName: "shared", Endpoints: []*endpoint.LocalityLbEndpoints{{}}}
					initial.Endpoints = map[string]*endpoint.ClusterLoadAssignment{"shared": explicit}
				}
				require.NoError(t, c.ApplyResources(t.Context(), "node1", ResourceMutations{Upserted: initial}, nil, TypeURLCallbacks{}))
				before := requestSnapshotForTest(t, c, "node1", typeurl.Cluster)
				oldAssignment := before.GetResources(typeurl.Endpoint.URL())["shared"]
				var mutation ResourceMutations
				var replacement *endpoint.ClusterLoadAssignment
				switch mode {
				case "remove-one-reference":
					mutation.Removed.Clusters = map[string]*cluster.Cluster{"a": nil}
				case "remove-last-reference":
					mutation.Removed.Clusters = initial.Clusters
				case "retarget-one-reference":
					mutation.Upserted.Clusters = map[string]*cluster.Cluster{"a": strictTestEDSCluster("a", "new")}
				case "replace-explicit":
					replacement = &endpoint.ClusterLoadAssignment{ClusterName: "shared"}
					mutation.Upserted.Endpoints = map[string]*endpoint.ClusterLoadAssignment{"shared": replacement}
				case "remove-explicit":
					mutation.Removed.Endpoints = initial.Endpoints
				}
				require.NoError(t, c.ApplyResources(t.Context(), "node1", mutation, nil, TypeURLCallbacks{}))
				index := typeurl.Cluster
				if explicit != nil {
					index = typeurl.Endpoint
				}
				after := requestSnapshotForTest(t, c, "node1", index)
				projected := after.GetResources(typeurl.Endpoint.URL())
				if mode == "remove-last-reference" {
					require.Empty(t, projected)
				} else {
					require.Contains(t, projected, "shared")
					assignment := projected["shared"].(*endpoint.ClusterLoadAssignment)
					require.Empty(t, assignment.Endpoints)
					if replacement != nil {
						require.Same(t, replacement, assignment)
					} else if explicit == nil {
						require.Same(t, oldAssignment, assignment, "an unchanged shared projection should be reused")
					}
				}
				if mode == "retarget-one-reference" {
					require.Len(t, projected, 2)
					require.Contains(t, projected, "new")
				}
				if mode == "replace-explicit" {
					require.Same(t, replacement, c.GetResource("node1", typeurl.Endpoint, "shared"))
				} else {
					require.Nil(t, c.GetResource("node1", typeurl.Endpoint, "shared"), "synthetic assignments must not enter desired state")
				}
				require.Same(t, oldAssignment, before.GetResources(typeurl.Endpoint.URL())["shared"], "published maps must remain immutable")
				if mode == "remove-one-reference" {
					require.Equal(t, before.GetVersion(typeurl.Endpoint.URL()), after.GetVersion(typeurl.Endpoint.URL()),
						"removing one shared reference must not advance an unchanged EDS projection")
				} else {
					require.NotEqual(t, before.GetVersion(typeurl.Endpoint.URL()), after.GetVersion(typeurl.Endpoint.URL()),
						"a changed EDS projection must advance its wire version")
				}
				require.Nil(t, before.GetVersionMap(typeurl.Endpoint.URL()))
				require.NoError(t, CheckSnapshotConsistency(after))
			})
		}
	}
}

func TestPendingCLARemovalNACKRestoresExplicitAssignment(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			logger := slog.New(slog.DiscardHandler)
			if strict {
				logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
			}
			c := NewCache(logger, strict, WithNodeIDs("coverage-node")).(*cacheImpl)
			original := &endpoint.ClusterLoadAssignment{
				ClusterName: "shared",
				Policy:      &endpoint.ClusterLoadAssignment_Policy{OverprovisioningFactor: wrapperspb.UInt32(123)},
			}
			require.NoError(t, c.ApplyResources(t.Context(), "coverage-node", ResourceMutations{Upserted: xds.Resources{
				Clusters:  map[string]*cluster.Cluster{"cluster": strictTestEDSCluster("cluster", "shared")},
				Endpoints: map[string]*endpoint.ClusterLoadAssignment{"shared": original},
			}}, nil, TypeURLCallbacks{}))
			cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
			cds.reply(t, cds.receive(t), "")
			eds := coverageStream{cache: c, id: 2, typeURL: typeurl.Endpoint.URL()}
			eds.reply(t, eds.receive(t, "shared"), "", "shared")
			baseline := mustSnapshot(t, c, "coverage-node")

			// With no open EDS watch and no caller lifecycle or WaitGroup, this
			// removal must still retain its response inverse. Unlike an orphan's
			// omission, a referenced CLA is replaced by a named empty assignment.
			require.NoError(t, c.ApplyResource(t.Context(), "coverage-node", typeurl.Endpoint, "shared", nil, nil, nil))
			require.Nil(t, c.GetResource("coverage-node", typeurl.Endpoint, "shared"))
			require.Same(t, baseline, mustSnapshot(t, c, "coverage-node"), "removal remains unpublished")
			response := eds.receive(t, "shared")
			require.Len(t, response.Resources, 1)
			var projected endpoint.ClusterLoadAssignment
			require.NoError(t, response.Resources[0].UnmarshalTo(&projected))
			require.Equal(t, "shared", projected.ClusterName)
			require.Nil(t, projected.Policy)
			eds.reply(t, response, "rejected empty assignment", "shared")
			require.NotNil(t, c.GetResource("coverage-node", typeurl.Endpoint, "shared"))
			require.Same(t, original, c.GetResource("coverage-node", typeurl.Endpoint, "shared"))

			corrected := eds.receive(t, "shared")
			require.NotEqual(t, baseline.GetVersion(typeurl.Endpoint.URL()), corrected.VersionInfo,
				"restoring the old contents requires a corrective wire version")
			eds.reply(t, corrected, "", "shared")
			c.getNodeState("coverage-node").requireNoRollbackOwners(t)
		})
	}
}
