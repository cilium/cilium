// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"log/slog"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// BenchmarkRollbackDependencyMaintenance holds one dependent relationship and
// an increasing number of unrelated, unresolved responses. Seed through the
// production API/watch path, then isolate the maintenance done under the cache
// lock: absent-name pruning and collecting live prerequisite transactions.
func BenchmarkRollbackDependencyMaintenance(b *testing.B) {
	for _, unrelated := range []int{0, 64, 512} {
		for _, operation := range []string{"prune-absent", "live-transactions"} {
			b.Run(fmt.Sprintf("unrelated=%d/%s", unrelated, operation), func(b *testing.B) {
				const nodeID = "benchmark-node"
				c := NewCache(slog.New(slog.DiscardHandler), false, WithNodeIDs(nodeID)).(*cacheImpl)
				triggeringChange := &secret.Secret{Name: "secret-0"}
				for i := range unrelated + 1 {
					resource := triggeringChange
					if i != 0 {
						resource = &secret.Secret{Name: fmt.Sprintf("secret-%d", i)}
					}
					if err := c.ApplyResource(b.Context(), nodeID, typeurl.Secret, resource.Name, resource, nil, nil); err != nil {
						b.Fatal(err)
					}
					request := &cache.Request{Node: &core.Node{Id: nodeID},
						TypeUrl: typeurl.Secret.URL(), ResourceNames: []string{resource.Name}}
					responses := make(chan cache.Response, 1)
					cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(request.ResourceNames, false), responses)
					if err != nil {
						b.Fatal(err)
					}
					<-responses // Collect each response, but leave it unacknowledged.
					cancel()
				}
				if err := c.ApplyResources(b.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
					Secrets:   map[string]*secret.Secret{triggeringChange.Name: triggeringChange},
					Listeners: map[string]*listener.Listener{"dependent": {Name: "dependent"}},
				}}, nil, TypeURLCallbacks{}); err != nil {
					b.Fatal(err)
				}
				state := c.getNodeState(nodeID)
				c.mutex.Lock()
				defer c.mutex.Unlock()
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if operation == "prune-absent" {
						state.rollbacks.pruneAbsentDependentResource(state, typeurl.Listener, "absent")
					} else {
						transactions := state.rollbacks.liveDependencyTransactions(state)
						if transactions.Empty() {
							b.Fatal("missing prerequisite transaction")
						}
					}
				}
				b.StopTimer()
			})
		}
	}

}

// BenchmarkNACKTransactionSelection measures only preparing a NACK correction,
// with independent transactions coalesced into one response. Seed and supersede
// half the triggering resource changes through production APIs, then reuse the
// uncommitted batch so setup and response encoding stay outside this measurement.
func BenchmarkNACKTransactionSelection(b *testing.B) {
	for _, strict := range []bool{false, true} {
		for _, count := range []int{2, 64} {
			b.Run(fmt.Sprintf("strict=%t/transactions=%d", strict, count), func(b *testing.B) {
				const nodeID = "benchmark-node"
				c := NewCache(slog.New(slog.DiscardHandler), strict, WithNodeIDs(nodeID)).(*cacheImpl)
				for i := range count {
					name := fmt.Sprintf("resource-%d", i)
					if err := c.ApplyResources(b.Context(), nodeID, ResourceMutations{Upserted: xds.Resources{
						Listeners: map[string]*listener.Listener{name: {Name: name}},
						Clusters:  map[string]*cluster.Cluster{name: {Name: name}},
					}}, nil, TypeURLCallbacks{}); err != nil {
						b.Fatal(err)
					}
				}
				request := &cache.Request{Node: &core.Node{Id: nodeID}, TypeUrl: typeurl.Listener.URL()}
				responses := make(chan cache.Response, 1)
				cancel, err := c.CreateWatch(request, stream.NewSotwSubscription(nil, true), responses)
				if err != nil {
					b.Fatal(err)
				}
				<-responses
				cancel()
				state := c.getNodeState(nodeID)
				var rollbacks []Rollback
				for response := range state.rollbacks.responses.Members() {
					if response.typeURL == typeurl.Listener {
						rollbacks = append(rollbacks, response)
					}
				}
				if len(rollbacks) != 1 {
					b.Fatalf("expected one coalesced LDS inverse, got %d", len(rollbacks))
				}
				for i := range count / 2 {
					name := fmt.Sprintf("resource-%d", i)
					if err := c.ApplyResource(b.Context(), nodeID, typeurl.Listener, name,
						&listener.Listener{Name: name, StatPrefix: "independent"}, nil, nil); err != nil {
						b.Fatal(err)
					}
				}
				tx := c.beginResourceTransaction(b.Context(), nodeID)
				defer tx.complete()
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if _, err := state.rollbacks.prepareRevertLocked(&tx, rollbacks); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
			})
		}
	}
}
