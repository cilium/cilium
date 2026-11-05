// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"runtime"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// BenchmarkSotWResponseCoverage measures immutable response bookkeeping for
// empty, single-name, larger partial, and full responses selected by the cache.
func BenchmarkSotWResponseCoverage(b *testing.B) {
	resources := make([]cache_types.Resource, 64)
	names := make([]string, len(resources))
	for i := range resources {
		names[i] = fmt.Sprintf("listener-%d", i)
		resources[i] = &listener.Listener{Name: names[i]}
	}
	snapshot, err := cache.NewSnapshot("version", map[string][]cache_types.Resource{
		typeurl.Listener.URL(): resources,
	})
	if err != nil {
		b.Fatal(err)
	}
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, nil)
	if err := snapshotCache.SetSnapshot(b.Context(), "node", snapshot); err != nil {
		b.Fatal(err)
	}
	for _, tt := range []struct {
		name      string
		requested []string
	}{
		{name: "empty", requested: []string{"missing"}},
		{name: "single", requested: names[:1]},
		{name: "subset-8", requested: names[:8]},
		{name: "subset-32", requested: names[:32]},
		{name: "subset-63", requested: names[:63]},
		{name: "named-full", requested: names},
		{name: "wildcard"},
	} {
		b.Run(tt.name, func(b *testing.B) {
			response, err := snapshotCache.Fetch(WithSnapshotPublication(b.Context(), 1, snapshot), &discovery.DiscoveryRequest{
				Node: &core.Node{Id: "node"}, TypeUrl: typeurl.Listener.URL(), ResourceNames: tt.requested,
			})
			if err != nil {
				b.Fatal(err)
			}
			var covered cache.Response
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				covered = WithResponseCoverage(response, 1, snapshot)
			}
			runtime.KeepAlive(covered)
		})
	}
}
