// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"log/slog"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// BenchmarkBulkResourceWaitPreparation measures production bulk transactions,
// with and without caller ACK waits. The immutable inputs are prepared outside
// the measurement: semantic no-ops use distinct protobuf pointers, as freshly
// computed resources would, while changed resources alternate desired states.
func BenchmarkBulkResourceWaitPreparation(b *testing.B) {
	for _, count := range []int{1, 64} {
		for _, mode := range []string{"canonical-noop", "semantic-noop", "mixed", "changed"} {
			if mode == "mixed" && count == 1 {
				continue // A mixed transaction needs both changed and unchanged names.
			}
			for _, wait := range []bool{false, true} {
				b.Run(fmt.Sprintf("resources=%d/%s/wait=%t", count, mode, wait), func(b *testing.B) {
					const nodeID = "benchmark-node"
					c := NewCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
					var inputs [2]ResourceMutations
					for version := range inputs {
						listeners := make(map[string]*listener.Listener, count)
						for i := range count {
							name := fmt.Sprintf("listener-%d", i)
							value := uint32(1)
							if mode == "changed" || mode == "mixed" && i%2 == 0 {
								value += uint32(version)
							}
							listeners[name] = &listener.Listener{
								Name:                          name,
								PerConnectionBufferLimitBytes: wrapperspb.UInt32(value),
							}
						}
						inputs[version] = ResourceMutations{Upserted: xds.Resources{Listeners: listeners}}
					}
					seed := inputs[0]
					if mode == "semantic-noop" || mode == "mixed" {
						// Unchanged entries retain these canonical pointers, so every
						// candidate still needs semantic comparison on every iteration.
						seed.Upserted.Listeners = make(map[string]*listener.Listener, count)
						for name, resource := range inputs[0].Upserted.Listeners {
							seed.Upserted.Listeners[name] = proto.Clone(resource).(*listener.Listener)
						}
					}
					if err := c.ApplyResources(b.Context(), nodeID, seed, nil, typeurl.Set{}); err != nil {
						b.Fatal(err)
					}
					waits := typeurl.NewSet(typeurl.Listener)
					b.ReportAllocs()
					b.ResetTimer()
					for i := range b.N {
						var wg *completion.WaitGroup
						if wait {
							wg = completion.NewWaitGroup(b.Context())
						}
						version := 0
						if mode != "canonical-noop" {
							version = (i + 1) % len(inputs)
						}
						if err := c.ApplyResources(b.Context(), nodeID, inputs[version], wg, waits); err != nil {
							b.Fatal(err)
						}
						if wg != nil {
							// Cancel each caller wait so registrations do not
							// accumulate. Cache-owned rollback remains independent of it.
							wg.Cancel()
						}
					}
				})
			}
		}
	}
}

// BenchmarkSnapshotCLAProjection exercises the production generator with
// missing, explicit and shared EDS assignments, and with non-EDS Clusters.
func BenchmarkSnapshotCLAProjection(b *testing.B) {
	for _, tc := range []struct {
		count int
		mode  string
	}{
		{32, "missing"}, {256, "missing"}, {1024, "missing"},
		{1024, "explicit"}, {1024, "shared"}, {1024, "static"},
	} {
		b.Run(fmt.Sprintf("clusters=%d/%s", tc.count, tc.mode), func(b *testing.B) {
			const nodeID = "benchmark-node"
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
			clusters := make(map[string]*cluster.Cluster, tc.count)
			upserted := xds.Resources{Clusters: clusters}
			if tc.mode == "explicit" {
				upserted.Endpoints = make(map[string]*endpoint.ClusterLoadAssignment, tc.count)
			}
			for i := range tc.count {
				name := fmt.Sprintf("cluster-%d", i)
				clusters[name] = &cluster.Cluster{
					Name:                 name,
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
				}
				switch tc.mode {
				case "shared":
					clusters[name].EdsClusterConfig = &cluster.Cluster_EdsClusterConfig{ServiceName: "shared"}
				case "static":
					clusters[name].ClusterDiscoveryType = &cluster.Cluster_Type{Type: cluster.Cluster_STATIC}
				case "explicit":
					upserted.Endpoints[name] = &endpoint.ClusterLoadAssignment{ClusterName: name}
				}
			}
			if err := c.ApplyResources(b.Context(), nodeID,
				ResourceMutations{Upserted: upserted}, nil, typeurl.Set{}); err != nil {
				b.Fatal(err)
			}
			state := c.getNodeState(nodeID)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := c.generateSnapshotFromState(state); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSnapshotCLAProjectionIncrementally retargets an existing EDS
// population. Finalization must remove old synthetic assignments and project
// the new ones without scanning every Cluster for each missing assignment.
func BenchmarkSnapshotCLAProjectionIncrementally(b *testing.B) {
	for _, count := range []int{32, 256, 1024} {
		b.Run(fmt.Sprintf("clusters=%d", count), func(b *testing.B) {
			const nodeID = "benchmark-node"
			c := newCache(slog.New(slog.DiscardHandler), WithNodeIDs(nodeID))
			var input [2]ResourceMutations
			for version := range input {
				clusters := make(map[string]*cluster.Cluster, count)
				for i := range count {
					name := fmt.Sprintf("cluster-%d", i)
					clusters[name] = &cluster.Cluster{
						Name: name, ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
						EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{ServiceName: fmt.Sprintf("service-%d-%d", version, i)},
					}
				}
				input[version].Upserted.Clusters = clusters
			}
			if err := c.ApplyResources(b.Context(), nodeID, input[0], nil, typeurl.Set{}); err != nil {
				b.Fatal(err)
			}
			state := c.getNodeState(nodeID)
			previous, err := c.generateSnapshotFromStateIncrementally(state, nil, typeurl.All())
			if err != nil {
				b.Fatal(err)
			}
			if err := c.ApplyResources(b.Context(), nodeID, input[1], nil, typeurl.Set{}); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := c.generateSnapshotFromStateIncrementally(state, previous, typeurl.NewSet(typeurl.Cluster)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
