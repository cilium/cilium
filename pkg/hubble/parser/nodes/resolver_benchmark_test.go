// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nodes

import (
	"net/netip"
	"testing"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/identity"
)

var benchmarkLabels []string

func benchmarkResolver(b *testing.B, withIPCache bool) *Resolver {
	b.Helper()
	ipc := newTestIPCache(b)
	r := NewResolver(ipc, cmtypes.ClusterInfo{ID: localClusterID, Name: localCluster}, nil)
	r.NodeUpsert(nodeWithAddresses(localCluster, "node-a", localClusterID,
		map[string]string{
			"kubernetes.io/hostname":        "node-a",
			"topology.kubernetes.io/region": "region-a",
			"topology.kubernetes.io/zone":   "zone-a",
		}, "192.0.2.10"))
	if withIPCache {
		upsertHost(b, ipc, "10.0.0.1", "192.0.2.10")
		upsertHost(b, ipc, "10.0.0.2", "192.0.2.10")
	}
	return r
}

func BenchmarkResolverCacheHitBothDirections(b *testing.B) {
	r := benchmarkResolver(b, true)
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	hint := allocatedHint(localClusterID)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkLabels = r.GetNodeLabels(src, hint)
		benchmarkLabels = r.GetNodeLabels(dst, hint)
	}
}

func BenchmarkResolverIPCacheMiss(b *testing.B) {
	r := benchmarkResolver(b, false)
	ip := netip.MustParseAddr("10.0.0.1")
	hint := allocatedHint(localClusterID)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkLabels = r.GetNodeLabels(ip, hint)
	}
}

func BenchmarkResolverDirectNodeHit(b *testing.B) {
	r := benchmarkResolver(b, false)
	ip := netip.MustParseAddr("192.0.2.10")
	hint := allocatedHint(localClusterID)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkLabels = r.GetNodeLabels(ip, hint)
	}
}

func BenchmarkResolverUnknownProvenanceMiss(b *testing.B) {
	r := benchmarkResolver(b, true)
	ip := netip.MustParseAddr("10.0.0.1")
	hint := getters.NodeClusterHint{Identity: identity.GetMinimalAllocationIdentity(localClusterID)}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		benchmarkLabels = r.GetNodeLabels(ip, hint)
	}
}
