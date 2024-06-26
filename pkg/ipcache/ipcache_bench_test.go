// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
)

type dummyOwner struct{}

func (d *dummyOwner) UpdateIdentities(added, deleted identity.IdentityMap) {}
func (d *dummyOwner) GetNodeSuffix() string {
	return "foo"
}

func BenchmarkInjectLabels(b *testing.B) {

	ctx, cancel := context.WithCancel(context.Background())
	alloc := cache.NewCachingIdentityAllocator(&dummyOwner{})
	//<-alloc.InitIdentityAllocator(nil)
	PolicyHandler = &mockUpdater{
		identities: make(map[identity.NumericIdentity]labels.LabelArray),
	}
	ipc := NewIPCache(&Configuration{
		Context:           ctx,
		IdentityAllocator: alloc,
		PolicyHandler:     PolicyHandler,
		DatapathHandler:   &mockTriggerer{},
	})

	addr := netip.MustParseAddr("1.0.0.0")
	lbls := labels.NewLabelsFromSortedList(labels.LabelSourceCIDRGroup + ":foo=bar")
	b.ResetTimer()

	prefixes := make([]netip.Prefix, 0, b.N)

	for i := 0; i < b.N; i++ {
		pfx := netip.PrefixFrom(addr, 30)
		for j := 0; j < 4; j++ {
			addr = addr.Next()
		}
		prefixes = append(prefixes, ipc.metadata.upsertLocked(pfx, source.Kubernetes, "cidr-policy", lbls)...)
		if i%1000 == 0 {
			b.Log(i)
		}
	}
	b.Logf("%d", len(prefixes))
	b.Log(addr.String())
	_, err := ipc.doInjectLabels(ctx, prefixes)
	if err != nil {
		b.Fatal(err)
	}

	b.StopTimer()

	// sanity checks
	require.Len(b, ipc.ipToIdentityCache, b.N)

	b.Cleanup(func() {
		cancel()
	})

}
