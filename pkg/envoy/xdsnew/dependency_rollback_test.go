// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// Strict cases also exercise the debug-only snapshot projection invariant.
func newDependencyTestCache(t *testing.T, strict bool, nodeID string) *cacheImpl {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	if strict {
		logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	}
	return NewCache(logger, strict, WithNodeIDs(nodeID)).(*cacheImpl)
}

func TestCoalescedDependentTransactionWaiters(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, phase := range []string{"unpublished", "in-flight", "superseded"} {
			for _, reject := range []bool{false, true} {
				t.Run(fmt.Sprintf("strict=%t/%s/reject=%t", strict, phase, reject), func(t *testing.T) {
					const nodeID = "coverage-node"
					c := newDependencyTestCache(t, strict, nodeID)
					cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
					a := &cluster.Cluster{Name: "a"}
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "a", a, nil, nil))
					var response *discovery.DiscoveryResponse
					if phase == "in-flight" {
						response = cds.receive(t)
					}

					// B and C reuse A but wait only for SDS. Their inverses coalesce
					// to one s1 entry; both callers must still learn A's rejection.
					results := [2]chan error{make(chan error, 1), make(chan error, 1)}
					var last *tls.Secret
					for i := range results {
						wg := completion.NewWaitGroup(t.Context())
						t.Cleanup(wg.Cancel)
						var callbacks TypeURLCallbacks
						callbacks.Set(typeurl.Secret, func(err error) { results[i] <- err })
						last = &tls.Secret{Name: "s1"}
						if i == 1 {
							last.Type = &tls.Secret_GenericSecret{GenericSecret: &tls.GenericSecret{}}
						}
						require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
							Clusters: map[string]*cluster.Cluster{"a": a},
							Secrets:  map[string]*tls.Secret{"s1": last},
						}}, wg, callbacks))
					}
					if phase == "unpublished" {
						response = cds.receive(t)
					}
					var newer *cluster.Cluster
					if phase == "superseded" {
						response = cds.receive(t)
						newer = &cluster.Cluster{Name: "a", PerConnectionBufferLimitBytes: wrapperspb.UInt32(2)}
						require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, newer.Name, newer, nil, nil))
					}
					if reject {
						cds.reply(t, response, "rejected a")
						for _, result := range results {
							select {
							case err := <-result:
								require.ErrorContains(t, err, "rejected a")
							default:
								t.Fatal("dependent SDS wait did not receive the CDS NACK")
							}
						}
						require.Nil(t, c.GetResource(nodeID, typeurl.Secret, "s1"))
						if newer != nil {
							require.Same(t, newer, c.GetResource(nodeID, typeurl.Cluster, "a"),
								"superseding a prerequisite protects its new value, not the dependent transaction members")
						}
					} else {
						cds.reply(t, response, "")
						// An ACK releases the prerequisite, not B/C's SDS waits.
						// A later unrelated edit/NACK of A must not reject them.
						require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "a",
							&cluster.Cluster{Name: "a", PerConnectionBufferLimitBytes: wrapperspb.UInt32(1)}, nil, nil))
						cds.reply(t, cds.receive(t), "rejected later a")
						for _, result := range results {
							requireCoveragePending(t, result)
						}
						got := c.GetResource(nodeID, typeurl.Secret, "s1")
						require.NotNil(t, got)
						require.Same(t, last, got)
						sds := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
						sds.reply(t, sds.receive(t, "s1"), "", "s1")
						for _, result := range results {
							require.NoError(t, <-result)
						}
					}
					require.Zero(t, c.completionCbs.PendingCompletionCount())
				})
			}
		}
	}
}

func TestDependentRollbackCannotRestoreRejectedPredecessor(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, phase := range []string{"unpublished", "in-flight"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, phase), func(t *testing.T) {
				const nodeID = "coverage-node"
				c := newDependencyTestCache(t, strict, nodeID)
				t.Cleanup(func() {
					c.completionCbs.OnStreamClosed(1, nil)
					c.completionCbs.OnStreamClosed(2, nil)
				})
				sds := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				cds := coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
				a := &tls.Secret{Name: "s1"}
				b := &tls.Secret{Name: "s1", Type: &tls.Secret_GenericSecret{GenericSecret: &tls.GenericSecret{}}}
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Secret, "s1", a, nil, nil))
				responseA := sds.receive(t, "s1")
				prerequisite := &cluster.Cluster{Name: "prerequisite"}
				require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "prerequisite", prerequisite, nil, nil))
				var response *discovery.DiscoveryResponse
				if phase == "in-flight" {
					response = cds.receive(t)
				}
				// B's inverse belongs both to SDS and to the reused pending CDS
				// prerequisite. Rejecting A must rebase both owners, including a
				// prerequisite whose publication has not yet created a lifecycle.
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Clusters: map[string]*cluster.Cluster{"prerequisite": prerequisite},
					Secrets:  map[string]*tls.Secret{"s1": b},
				}}, nil, TypeURLCallbacks{}))
				sds.reply(t, responseA, "rejected A", "s1")
				require.Same(t, b, c.GetResource(nodeID, typeurl.Secret, "s1"), "independently newer B remains desired")
				if phase == "unpublished" {
					response = cds.receive(t)
				}
				cds.reply(t, response, "rejected prerequisite")
				require.Nil(t, c.GetResource(nodeID, typeurl.Secret, "s1"), "B's dependent inverse must bypass rejected A")
				require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, "prerequisite"))
			})
		}
	}
}

func TestNACKBatchPreservesSupersededIndependentTransaction(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			const nodeID = "coverage-node"
			c := newDependencyTestCache(t, strict, nodeID)
			t.Cleanup(func() {
				c.completionCbs.OnStreamClosed(1, nil)
				c.completionCbs.OnStreamClosed(2, nil)
			})
			first := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
			second := coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
			sibling := &tls.Secret{Name: "first"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Clusters: map[string]*cluster.Cluster{"first": {Name: "first"}},
				Secrets:  map[string]*tls.Secret{"first": sibling},
			}}, nil, TypeURLCallbacks{}))
			first.receive(t)
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Clusters: map[string]*cluster.Cluster{"second": {Name: "second"}},
				Secrets:  map[string]*tls.Secret{"second": {Name: "second"}},
			}}, nil, TypeURLCallbacks{}))
			response := second.receive(t)
			newer := &cluster.Cluster{Name: "first", AltStatName: "independent"}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "first", newer, nil, nil))
			// Both older transactions are selected, but only "second" still
			// has its rejected value. That triggering resource change cannot make "first"'s guarded
			// transaction members eligible for rollback.
			second.reply(t, response, "rejected CDS")
			require.Same(t, newer, c.GetResource(nodeID, typeurl.Cluster, "first"))
			require.Same(t, sibling, c.GetResource(nodeID, typeurl.Secret, "first"))
			require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, "second"))
			require.Nil(t, c.GetResource(nodeID, typeurl.Secret, "second"))
		})
	}
}

func TestNACKBatchPreservesSupersededListenerTransactionMembers(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, api := range []string{"single", "bulk"} {
			for _, tc := range []struct {
				name      string
				coalesced bool
				recovery  string
			}{
				{"separate-responses", false, ""},
				{"coalesced-response", true, ""},
				{"separate-responses/later-caller-revert", false, "caller"},
				{"coalesced-response/later-caller-revert", true, "caller"},
				{"separate-responses/later-response-nack", false, "response"},
				{"coalesced-response/later-response-nack", true, "response"},
			} {
				t.Run(fmt.Sprintf("strict=%t/api=%s/%s", strict, api, tc.name), func(t *testing.T) {
					const nodeID = "coverage-node"
					c := newDependencyTestCache(t, strict, nodeID)
					t.Cleanup(func() {
						c.completionCbs.OnStreamClosed(1, nil)
						c.completionCbs.OnStreamClosed(2, nil)
					})
					lds := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
					cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
					listenerForCluster := func(name, clusterName string) *listener.Listener {
						return &listener.Listener{Name: name, FilterChains: []*listener.FilterChain{{
							Filters: []*listener.Filter{{
								Name: "envoy.filters.network.tcp_proxy",
								ConfigType: &listener.Filter_TypedConfig{TypedConfig: mustAny(t, &tcp.TcpProxy{
									StatPrefix:       name,
									ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: clusterName},
								})},
							}},
						}}}
					}
					clusterA, clusterB := &cluster.Cluster{Name: "cluster-a"}, &cluster.Cluster{Name: "cluster-b"}
					listenerA, listenerB := listenerForCluster("listener-a", clusterA.Name), listenerForCluster("listener-b", clusterB.Name)
					require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
						Listeners: map[string]*listener.Listener{listenerA.Name: listenerA},
						Clusters:  map[string]*cluster.Cluster{clusterA.Name: clusterA},
					}}, nil, TypeURLCallbacks{}))
					if !tc.coalesced {
						lds.receive(t)
						lds = coverageStream{cache: c, id: 2, typeURL: typeurl.Listener.URL()}
					}
					require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
						Listeners: map[string]*listener.Listener{listenerB.Name: listenerB},
						Clusters:  map[string]*cluster.Cluster{clusterB.Name: clusterB},
					}}, nil, TypeURLCallbacks{}))
					rejected := lds.receive(t)
					require.Len(t, rejected.Resources, 2, "the rejected response must contain both listeners")
					clusters := cds.receive(t)
					require.Len(t, clusters.Resources, 2)
					cds.reply(t, clusters, "")

					newer := proto.Clone(listenerA).(*listener.Listener)
					newer.PerConnectionBufferLimitBytes = wrapperspb.UInt32(4096)
					if api == "single" {
						require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, newer.Name, newer, nil, nil))
					} else {
						require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
							Listeners: map[string]*listener.Listener{newer.Name: newer},
						}}, nil, TypeURLCallbacks{}))
					}
					var caller Rollback
					var memberResponse *discovery.DiscoveryResponse
					expectedCluster := clusterA
					if tc.recovery != "" {
						expectedCluster = proto.Clone(clusterA).(*cluster.Cluster)
						expectedCluster.AltStatName = "independent"
						if tc.recovery == "caller" {
							var err error
							caller, err = c.ApplyResourceWithRollback(t.Context(), nodeID, typeurl.Cluster, clusterA.Name, expectedCluster, nil, nil)
							require.NoError(t, err)
							require.NotNil(t, caller)
							t.Cleanup(func() {
								if caller != nil {
									caller.Finalize()
								}
							})
						} else {
							require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, clusterA.Name, expectedCluster, nil, nil))
							memberResponse = cds.receive(t)
						}
					}
					// B's rejected value remains current, but it belongs to a different
					// API transaction. Coalescing cannot make A's members eligible.
					lds.reply(t, rejected, "rejected old LDS response")
					require.Same(t, newer, c.GetResource(nodeID, typeurl.Listener, listenerA.Name))
					require.Nil(t, c.GetResource(nodeID, typeurl.Listener, listenerB.Name))
					require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, clusterB.Name))
					current := c.GetResource(nodeID, typeurl.Cluster, clusterA.Name)
					require.NotNil(t, current, "the superseded Listener's ACKed transaction member must survive")
					require.Same(t, expectedCluster, current)
					if tc.recovery != "" {
						// Preserving a member also means preserving later inverses which
						// restore it. The LDS NACK must not rebase this target to absence.
						if caller != nil {
							err := caller.Revert()
							caller = nil
							require.NoError(t, err)
						} else {
							cds.reply(t, memberResponse, "rejected later CDS response")
						}
						current = c.GetResource(nodeID, typeurl.Cluster, clusterA.Name)
						require.NotNil(t, current, "later rollback must restore the preserved transaction member")
						require.Same(t, clusterA, current)
						require.Same(t, newer, c.GetResource(nodeID, typeurl.Listener, listenerA.Name))
					}
				})
			}
		}
	}
}

func TestNACKBatchRevertsMembersOfEligibleTransactions(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, shape := range []string{"multiple-triggering-changes", "coalesced-predecessors", "delivered-predecessors"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, shape), func(t *testing.T) {
				const nodeID = "coverage-node"
				c := newDependencyTestCache(t, strict, nodeID)
				t.Cleanup(func() {
					c.completionCbs.OnStreamClosed(1, nil)
					c.completionCbs.OnStreamClosed(2, nil)
				})
				cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
				sds := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
				first := &cluster.Cluster{Name: "first"}
				upserted := xds.Resources{
					Clusters: map[string]*cluster.Cluster{first.Name: first},
					Secrets:  map[string]*tls.Secret{"first": {Name: "first"}},
				}
				if shape == "multiple-triggering-changes" {
					upserted.Clusters["second"] = &cluster.Cluster{Name: "second"}
					upserted.Secrets["second"] = &tls.Secret{Name: "second"}
				}
				require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: upserted}, nil, TypeURLCallbacks{}))
				if shape == "delivered-predecessors" {
					cds.receive(t)
					cds = coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
				}
				if shape != "multiple-triggering-changes" {
					// The older transaction's distinct member remains current when a
					// newer transaction replaces its triggering resource change. Both belong to this chain.
					require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
						Clusters: map[string]*cluster.Cluster{first.Name: {Name: first.Name, AltStatName: "second"}},
						Secrets:  map[string]*tls.Secret{"second": {Name: "second"}},
					}}, nil, TypeURLCallbacks{}))
				}
				rejected := cds.receive(t)
				members := sds.receive(t, "first", "second")
				require.Len(t, members.Resources, 2)
				sds.reply(t, members, "", "first", "second")
				var newer *cluster.Cluster
				if shape == "multiple-triggering-changes" {
					// The other triggering resource change still authorizes rollback of the same transaction's
					// members, even though the first triggeringChange has an independently newer value.
					newer = &cluster.Cluster{Name: first.Name, AltStatName: "independent"}
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, first.Name, newer, nil, nil))
				}
				cds.reply(t, rejected, "rejected CDS")
				if newer == nil {
					require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, first.Name))
				} else {
					require.Same(t, newer, c.GetResource(nodeID, typeurl.Cluster, first.Name))
				}
				require.Nil(t, c.GetResource(nodeID, typeurl.Cluster, "second"))
				for _, name := range []string{"first", "second"} {
					require.Nil(t, c.GetResource(nodeID, typeurl.Secret, name),
						"an eligible transaction must revert every still-current member, including an ACKed one")
				}
			})
		}
	}
}

func TestNACKRebasesDependentWholeTransaction(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			const nodeID = "coverage-node"
			c := newDependencyTestCache(t, strict, nodeID)
			t.Cleanup(func() {
				for id := range int64(3) {
					c.completionCbs.OnStreamClosed(id+1, nil)
				}
			})
			sds := coverageStream{cache: c, id: 1, typeURL: typeurl.Secret.URL()}
			cds := coverageStream{cache: c, id: 2, typeURL: typeurl.Cluster.URL()}
			lds := coverageStream{cache: c, id: 3, typeURL: typeurl.Listener.URL()}
			transaction := func(value string) ResourceMutations {
				return ResourceMutations{Upserted: xds.Resources{
					Secrets: map[string]*tls.Secret{"secret": {Name: "secret", Type: &tls.Secret_GenericSecret{
						GenericSecret: &tls.GenericSecret{Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: value}}},
					}}},
					Clusters: map[string]*cluster.Cluster{"cluster": {Name: "cluster", AltStatName: value}},
				}}
			}
			baseline := transaction("baseline")
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, baseline, nil, TypeURLCallbacks{}))
			sds.reply(t, sds.receive(t, "secret"), "", "secret")
			cds.reply(t, cds.receive(t), "")
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, transaction("A"), nil, TypeURLCallbacks{}))
			rejected := sds.receive(t, "secret")
			cds.reply(t, cds.receive(t), "")

			prerequisite := &listener.Listener{Name: "prerequisite"}
			require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Listener, prerequisite.Name, prerequisite, nil, nil))
			prerequisiteResponse := lds.receive(t)
			later := transaction("B")
			later.Upserted.Listeners = map[string]*listener.Listener{prerequisite.Name: prerequisite}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, later, nil, TypeURLCallbacks{}))
			sds.reply(t, rejected, "rejected A", "secret")
			require.Same(t, later.Upserted.Clusters["cluster"], c.GetResource(nodeID, typeurl.Cluster, "cluster"))

			// B's dependency inverse would restore both members of A, including
			// its rejected Secret. It must bypass that whole predecessor, unlike
			// an independent inverse which restores only A's preserved Cluster.
			lds.reply(t, prerequisiteResponse, "rejected prerequisite")
			require.Nil(t, c.GetResource(nodeID, typeurl.Listener, prerequisite.Name))
			require.Same(t, baseline.Upserted.Secrets["secret"], c.GetResource(nodeID, typeurl.Secret, "secret"))
			require.Same(t, baseline.Upserted.Clusters["cluster"], c.GetResource(nodeID, typeurl.Cluster, "cluster"))
		})
	}
}

func TestUnsentDependencyHistoryIsBounded(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict=%t/reject=%t", strict, reject), func(t *testing.T) {
				const nodeID = "coverage-node"
				c := newDependencyTestCache(t, strict, nodeID)
				for i := range 100 {
					a := &cluster.Cluster{Name: "a", PerConnectionBufferLimitBytes: wrapperspb.UInt32(uint32(i + 1))}
					require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Cluster, "a", a, nil, nil))
					secret := &tls.Secret{Name: "s1", Type: &tls.Secret_GenericSecret{GenericSecret: &tls.GenericSecret{
						Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: fmt.Sprint(i)}},
					}}}
					require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
						Clusters: map[string]*cluster.Cluster{"a": a}, Secrets: map[string]*tls.Secret{"s1": secret},
					}}, nil, TypeURLCallbacks{}))
				}
				pending := c.getNodeState(nodeID).pendingPublication
				triggeringChanges, _ := pending.rollbacks.Get(typeurl.Cluster)
				dependents, _ := pending.dependents.Get(typeurl.Cluster)
				// No response has exposed an intermediate value. Two live names
				// need one prerequisite identity, not 100 historical generations.
				require.LessOrEqual(t, triggeringChanges[typeurl.Cluster]["a"].transactions.Len(), 1)
				require.Equal(t, 1, dependents[typeurl.Secret]["s1"].transactions.Len())

				cds := coverageStream{cache: c, id: 1, typeURL: typeurl.Cluster.URL()}
				response := cds.receive(t)
				if reject {
					cds.reply(t, response, "rejected initial a")
					for _, index := range []typeurl.Index{typeurl.Cluster, typeurl.Secret} {
						name := "a"
						if index == typeurl.Secret {
							name = "s1"
						}
						require.Nil(t, c.GetResource(nodeID, index, name))
					}
				} else {
					cds.reply(t, response, "")
					sds := coverageStream{cache: c, id: 2, typeURL: typeurl.Secret.URL()}
					sds.reply(t, sds.receive(t, "s1"), "", "s1")
					require.True(t, c.getNodeState(nodeID).rollbacks.responses.Empty())
				}
			})
		}
	}
}

func TestDependentWaitersRetainOnlyUnacknowledgedPrerequisites(t *testing.T) {
	const nodeID = "coverage-node"
	c := newCoverageCache(t)
	first := &endpoint.ClusterLoadAssignment{ClusterName: "e1"}
	second := &endpoint.ClusterLoadAssignment{ClusterName: "e2"}
	for _, value := range []*endpoint.ClusterLoadAssignment{first, second} {
		require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, value.ClusterName, value, nil, nil))
	}
	results := [2]chan error{make(chan error, 1), make(chan error, 1)}
	for i := range results {
		wg := completion.NewWaitGroup(t.Context())
		t.Cleanup(wg.Cancel)
		var callbacks TypeURLCallbacks
		callbacks.Set(typeurl.Secret, func(err error) { results[i] <- err })
		require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
			Endpoints: map[string]*endpoint.ClusterLoadAssignment{"e1": first, "e2": second},
			Secrets: map[string]*tls.Secret{"s1": {Name: "s1", Type: &tls.Secret_GenericSecret{GenericSecret: &tls.GenericSecret{
				Secret: &core.DataSource{Specifier: &core.DataSource_InlineString{InlineString: fmt.Sprint(i)}},
			}}}},
		}}, wg, callbacks))
	}

	eds := coverageStream{cache: c, id: 1}
	eds.reply(t, eds.receive(t, "e1"), "", "e1")
	// Both waits still require e2, but e1 is accepted. Their mutable partial
	// scopes must be independent, and a later e1 NACK must not fail either wait.
	require.NoError(t, c.ApplyResource(t.Context(), nodeID, typeurl.Endpoint, "e1",
		&endpoint.ClusterLoadAssignment{ClusterName: "e1", Endpoints: []*endpoint.LocalityLbEndpoints{{
			Locality: &core.Locality{Region: "new"},
		}}}, nil, nil))
	eds.reply(t, eds.receive(t, "e1"), "rejected later e1", "e1")
	for _, result := range results {
		requireCoveragePending(t, result)
	}
	eds.reply(t, eds.receive(t, "e2"), "rejected e2", "e2")
	for _, result := range results {
		select {
		case err := <-result:
			require.ErrorContains(t, err, "rejected e2")
		default:
			t.Fatal("remaining prerequisite NACK did not reject a dependent waiter")
		}
	}
	require.Nil(t, c.GetResource(nodeID, typeurl.Secret, "s1"))
	require.Zero(t, c.completionCbs.PendingCompletionCount())
}

func TestResponseNACKRestoresStillCurrentChildContent(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%t", strict), func(t *testing.T) {
			const nodeID = "coverage-node"
			c := newDependencyTestCache(t, strict, nodeID)
			lds := coverageStream{cache: c, id: 1, typeURL: typeurl.Listener.URL()}
			rds := coverageStream{cache: c, id: 2, typeURL: typeurl.Route.URL()}
			oldListener := strictTestListener(t, "l1", "r1")
			oldRoute := &route.RouteConfiguration{Name: "r1"}
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*listener.Listener{"l1": oldListener}, Routes: map[string]*route.RouteConfiguration{"r1": oldRoute},
			}}, nil, TypeURLCallbacks{}))
			lds.reply(t, lds.receive(t), "")
			rds.reply(t, rds.receive(t, "r1"), "", "r1")
			changedListener := strictTestListener(t, "l1", "r1")
			changedListener.TrafficDirection = core.TrafficDirection_INBOUND
			require.NoError(t, c.ApplyResources(t.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
				Listeners: map[string]*listener.Listener{"l1": changedListener},
				Routes:    map[string]*route.RouteConfiguration{"r1": {Name: "r1", IgnorePortInHostMatching: true}},
			}}, nil, TypeURLCallbacks{}))
			lds.reply(t, lds.receive(t), "rejected listener configuration")
			got := c.GetResource(nodeID, typeurl.Route, "r1")
			require.NotNil(t, got)
			require.Same(t, oldRoute, got, "strict reference recovery must not suppress transaction rollback")
		})
	}
}
