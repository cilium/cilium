// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// Observable rollback results alone cannot detect stale pointers in a secondary
// index. Check both directions after production transitions, including owners
// shared by named responses and names which disappear during coalescing.
func (r *rollbackState) requireDependentIndex(t *testing.T) {
	t.Helper()
	var expected typeurl.Map[map[string]set.Set[*rollbackLifecycle]]
	for lifecycle := range r.responses.Members() {
		if lifecycle.dependents == nil {
			continue
		}
		for index, entries := range *lifecycle.dependents {
			for name := range entries {
				typeURL := typeurl.Index(index)
				owners, _ := expected.Get(typeURL)
				if owners == nil {
					owners = make(map[string]set.Set[*rollbackLifecycle])
					expected.Set(typeURL, owners)
				}
				lifecycles := owners[name]
				lifecycles.Insert(lifecycle)
				owners[name] = lifecycles
			}
		}
	}
	require.Equal(t, expected.Len(), r.dependents.Len())
	for typeURL, owners := range expected.All() {
		actual, exists := r.dependents.Get(typeURL)
		require.True(t, exists)
		require.Len(t, actual, len(owners))
		for name, lifecycles := range owners {
			require.True(t, lifecycles.Equal(actual[name]), "%s %s owners differ", typeURL.URL(), name)
		}
	}
	for typeURL := range typeurl.Indices() {
		if !r.dependents.Has(typeURL) {
			owners, _ := r.dependents.Get(typeURL)
			require.Nil(t, owners)
		}
	}
}

func TestDependentRollbackIndexTracksNamedResponseOwners(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, outcome := range []string{"ACK", "NACK", "caller revert"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, outcome), func(t *testing.T) {
				c := NewCache(hivetest.Logger(t), strict, WithNodeIDs("coverage-node")).(*cacheImpl)
				state := c.getNodeState("coverage-node")
				s1, s2 := &secret.Secret{Name: "s1"}, &secret.Secret{Name: "s2"}
				secondType := typeurl.Secret
				mutations := ResourceMutations{Upserted: xds.Resources{
					Secrets: map[string]*secret.Secret{s1.Name: s1},
				}}
				require.NoError(t, c.ApplyResource(t.Context(), state.nodeID, typeurl.Secret, s1.Name, s1, nil, nil))
				if strict {
					// Strict ADS requires a named SDS subscription to cover the
					// whole group. Use distinct types to share dependent ownership;
					// non-strict ADS additionally exercises splitting one SDS group.
					secondType = typeurl.Cluster
					resource := &cluster.Cluster{Name: s2.Name}
					mutations.Upserted.Clusters = map[string]*cluster.Cluster{resource.Name: resource}
					require.NoError(t, c.ApplyResource(t.Context(), state.nodeID, secondType, resource.Name, resource, nil, nil))
				} else {
					mutations.Upserted.Secrets[s2.Name] = s2
					require.NoError(t, c.ApplyResource(t.Context(), state.nodeID, secondType, s2.Name, s2, nil, nil))
				}
				// Publish without consuming the prerequisite watches. Non-strict
				// SDS has one unsent owner which named responses will partition.
				requestSnapshotForTest(t, c, state.nodeID, typeurl.Listener)
				dependent := &listener.Listener{Name: "dependent"}
				mutations.Upserted.Listeners = map[string]*listener.Listener{dependent.Name: dependent}
				var caller Rollback
				if outcome == "caller revert" {
					var err error
					caller, err = c.ApplyResourcesWithRollback(t.Context(), state.nodeID, mutations, nil, TypeURLCallbacks{})
					require.NoError(t, err)
					t.Cleanup(func() {
						if caller != nil {
							caller.Finalize()
						}
					})
				} else {
					require.NoError(t, c.ApplyResources(t.Context(), state.nodeID, mutations, nil, TypeURLCallbacks{}))
				}
				state.rollbacks.requireDependentIndex(t)
				owners, _ := state.rollbacks.dependents.Get(typeurl.Listener)
				wantOwners := 1
				if strict {
					wantOwners = 2
				}
				require.Equal(t, wantOwners, owners[dependent.Name].Len())

				first := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				firstResponse := first.receive(t, s1.Name)
				state.rollbacks.requireDependentIndex(t)
				owners, _ = state.rollbacks.dependents.Get(typeurl.Listener)
				require.Equal(t, 2, owners[dependent.Name].Len(), "splitting prerequisites duplicates dependent ownership")
				second := coverageStream{cache: c, id: 2, typeURL: secondType.URL()}
				secondResponse := second.receive(t, s2.Name)
				state.rollbacks.requireDependentIndex(t)

				if caller != nil {
					// Restoring absence prunes the same name from both indexed owners,
					// exercising the set's map -> singleton -> empty transitions.
					require.NoError(t, caller.Revert())
					caller = nil
					state.rollbacks.requireDependentIndex(t)
					require.True(t, state.rollbacks.dependents.Empty())
					require.Nil(t, c.GetResource(state.nodeID, typeurl.Listener, dependent.Name))
					first.reply(t, firstResponse, "", s1.Name)
					second.reply(t, secondResponse, "second prerequisite rejected", s2.Name)
					state.rollbacks.requireDependentIndex(t)
					require.True(t, state.rollbacks.dependents.Empty())
					return
				}

				first.reply(t, firstResponse, "", s1.Name)
				state.rollbacks.requireDependentIndex(t)
				owners, _ = state.rollbacks.dependents.Get(typeurl.Listener)
				require.Equal(t, 1, owners[dependent.Name].Len(), "ACK releases only its response's ownership")
				require.Same(t, dependent, c.GetResource(state.nodeID, typeurl.Listener, dependent.Name))
				rejection := ""
				if outcome == "NACK" {
					rejection = "second prerequisite rejected"
				}
				second.reply(t, secondResponse, rejection, s2.Name)
				state.rollbacks.requireDependentIndex(t)
				require.True(t, state.rollbacks.dependents.Empty(), "last terminal owner must release the index")
				require.Equal(t, rejection == "", c.GetResource(state.nodeID, typeurl.Listener, dependent.Name) != nil)
				require.Same(t, s1, c.GetResource(state.nodeID, typeurl.Secret, s1.Name), "accepted prerequisite is independent")
			})
		}
	}
}

func TestDependentRollbackIndexTracksUnsentCoalescing(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprintf("published=%t", published), func(t *testing.T) {
			c := newCoverageCache(t)
			state := c.getNodeState("coverage-node")
			triggeringChange := &secret.Secret{Name: "triggering-change"}
			require.NoError(t, c.ApplyResource(t.Context(), state.nodeID, typeurl.Secret, triggeringChange.Name, triggeringChange, nil, nil))
			if published {
				requestSnapshotForTest(t, c, state.nodeID, typeurl.Cluster)
			}
			dependent := &listener.Listener{Name: "dependent"}
			require.NoError(t, c.ApplyResources(t.Context(), state.nodeID, ResourceMutations{Upserted: xds.Resources{
				Secrets:   map[string]*secret.Secret{triggeringChange.Name: triggeringChange},
				Listeners: map[string]*listener.Listener{dependent.Name: dependent},
			}}, nil, TypeURLCallbacks{}))
			state.rollbacks.requireDependentIndex(t)
			if !published {
				require.True(t, state.rollbacks.dependents.Empty(), "unpublished dependencies have no lifecycle")
				requestSnapshotForTest(t, c, state.nodeID, typeurl.Cluster)
			}
			state.rollbacks.requireDependentIndex(t)
			require.False(t, state.rollbacks.dependents.Empty())

			// Republishing an unconsumed triggering resource change coalesces and renormalizes its
			// dependencies. The surviving dependent must remain indexed.
			triggeringChange = &secret.Secret{Name: triggeringChange.Name, Type: &secret.Secret_ValidationContext{
				ValidationContext: &secret.CertificateValidationContext{AllowExpiredCertificate: true},
			}}
			require.NoError(t, c.ApplyResource(t.Context(), state.nodeID, typeurl.Secret, triggeringChange.Name, triggeringChange, nil, nil))
			requestSnapshotForTest(t, c, state.nodeID, typeurl.Cluster)
			state.rollbacks.requireDependentIndex(t)
			require.False(t, state.rollbacks.dependents.Empty())

			// Removal may still have live tombstone ownership from the published
			// Listener group. Preserve precisely those relationships until outcome.
			require.NoError(t, c.ApplyResources(t.Context(), state.nodeID, ResourceMutations{
				Upserted: xds.Resources{Secrets: map[string]*secret.Secret{triggeringChange.Name: triggeringChange}},
				Removed:  xds.Resources{Listeners: map[string]*listener.Listener{dependent.Name: nil}},
			}, nil, TypeURLCallbacks{}))
			state.rollbacks.requireDependentIndex(t)
			require.Nil(t, c.GetResource(state.nodeID, typeurl.Listener, dependent.Name))
			stream := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
			stream.reply(t, stream.receive(t, triggeringChange.Name), "triggering resource change rejected", triggeringChange.Name)
			state.rollbacks.requireDependentIndex(t)
			require.True(t, state.rollbacks.dependents.Empty())
			require.Nil(t, c.GetResource(state.nodeID, typeurl.Secret, triggeringChange.Name))
		})
	}
}

func TestFailedDependentPublicationPreservesIndex(t *testing.T) {
	for _, source := range []string{"API", "NACK"} {
		t.Run(source, func(t *testing.T) {
			c := newCoverageCache(t)
			state := c.getNodeState("coverage-node")
			triggeringChange := &secret.Secret{Name: "triggering-change"}
			require.NoError(t, c.ApplyResource(t.Context(), state.nodeID, typeurl.Secret, triggeringChange.Name, triggeringChange, nil, nil))
			stream := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
			response := stream.receive(t, triggeringChange.Name)
			dependent := &listener.Listener{Name: "dependent"}
			mutations := ResourceMutations{Upserted: xds.Resources{
				Secrets:   map[string]*secret.Secret{triggeringChange.Name: triggeringChange},
				Listeners: map[string]*listener.Listener{dependent.Name: dependent},
			}}
			require.NoError(t, c.ApplyResources(t.Context(), state.nodeID, mutations, nil, TypeURLCallbacks{}))
			state.rollbacks.requireDependentIndex(t)

			// Hold an LDS watch so the next dependent update attempts publication.
			lds := coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
			lds.reply(t, lds.receive(t), "")
			cancel, err := c.CreateWatch(&cache.Request{Node: &core.Node{Id: state.nodeID},
				TypeUrl: typeurl.Listener.URL(), VersionInfo: lds.version}, lds.sub, make(chan cache.Response, 1))
			require.NoError(t, err)
			t.Cleanup(cancel)
			failed := newMockSnapshotCache()
			failed.snapshots[state.nodeID] = mustSnapshot(t, c, state.nodeID)
			failed.setSnapshotErr = errors.New("publication failed")
			original := c.SnapshotCache
			c.SnapshotCache = failed
			t.Cleanup(func() { c.SnapshotCache = original })
			if source == "API" {
				mutations.Upserted.Listeners[dependent.Name] = &listener.Listener{Name: dependent.Name,
					PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}
				err = c.ApplyResources(t.Context(), state.nodeID, mutations, nil, TypeURLCallbacks{})
			} else {
				err = c.completionCbs.OnStreamRequest(stream.id, &discovery.DiscoveryRequest{
					TypeUrl: typeurl.Secret.URL(), ResponseNonce: response.Nonce, ResourceNames: []string{triggeringChange.Name},
					ErrorDetail: &status.Status{Message: "triggering resource change rejected"},
				})
			}
			require.ErrorIs(t, err, failed.setSnapshotErr)
			c.SnapshotCache = original
			state.rollbacks.requireDependentIndex(t)
			require.Same(t, dependent, c.GetResource(state.nodeID, typeurl.Listener, dependent.Name))
			if source == "NACK" {
				// Failed correction retains recovery for the next response/NACK.
				response = stream.receive(t, triggeringChange.Name)
			}
			stream.reply(t, response, "triggering resource change rejected", triggeringChange.Name)
			state.rollbacks.requireDependentIndex(t)
			require.True(t, state.rollbacks.dependents.Empty())
			require.Nil(t, c.GetResource(state.nodeID, typeurl.Listener, dependent.Name), "failed publication cannot detach earlier recovery")
		})
	}
}
