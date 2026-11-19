// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/time"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestNameCache(t *testing.T) {
	mappings := newNameCache()
	ips := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
	}
	require.False(t, mappings.add("empty."))
	require.Empty(t, mappings.names())
	for _, ip := range ips {
		require.True(t, mappings.add("cilium.io.", ip))
		require.False(t, mappings.add("cilium.io.", ip))
	}
	require.ElementsMatch(t, ips, mappings.lookup("cilium.io."))
	require.True(t, mappings.add("other.", ips[0]))

	// Filtering candidates must not change the global cache's IPs.
	noZombies := newNameIPSet()
	candidates := mappings.removalCandidates(mappings.names(), &noZombies)
	endpoint := fqdn.NewDNSCache(0)
	endpoint.Update(time.Now(), "cilium.io.", ips[:2], 3600)
	endpoint.RemoveKnown(candidates)
	require.Equal(t, set.NewSet(ips[2]), candidates["cilium.io."])
	require.ElementsMatch(t, ips, mappings.lookup("cilium.io."))

	// A shared IP must survive under one name when removed from another.
	// Unseen pairs in the live set must not be introduced during GC.
	alive := newNameIPSet()
	alive.add("cilium.io.", ips[0], ips[2], netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4"))
	alive.add("unseen.", ips[0])
	removed := mappings.removalCandidates(sets.New("cilium.io.", "other.", "unseen."), &alive)
	require.Equal(t, map[string]set.Set[netip.Addr]{
		"other.":     set.NewSet(ips[0]),
		"cilium.io.": set.NewSet(ips[1]),
	}, removed)
	require.ElementsMatch(t, ips, mappings.lookup("cilium.io."))
	mappings.remove(removed)
	require.ElementsMatch(t, []netip.Addr{ips[0], ips[2]}, mappings.lookup("cilium.io."))
	require.Equal(t, sets.New("cilium.io."), mappings.names())

	// Reducing to a singleton and then removing the last IP keeps no empty name.
	singleton := newNameIPSet()
	singleton.add("cilium.io.", ips[2])
	mappings.remove(mappings.removalCandidates(mappings.names(), &singleton))
	require.Equal(t, []netip.Addr{ips[2]}, mappings.lookup("cilium.io."))
	empty := newNameIPSet()
	mappings.remove(mappings.removalCandidates(mappings.names(), &empty))
	require.Empty(t, mappings.names())
}

func TestRemoveStaleIPs(t *testing.T) {
	const nameCount = 12
	ips := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"),
	}
	first, second := fqdn.NewDNSCache(0), fqdn.NewDNSCache(0)
	n := manager{cache: newNameCache(), updatedCaches: sets.New(first, second)}
	names := sets.New[string]()
	alive := newNameIPSet()
	now := time.Now()
	for i := range nameCount {
		name := fmt.Sprintf("name-%d.example.", i)
		names.Insert(name)
		n.cache.add(name, ips...)
		first.Update(now, name, ips[:1], 3600)
		if i%3 != 2 {
			second.Update(now, name, ips[1:2], 3600)
		}
		if i%3 == 0 {
			alive.add(name, ips[2])
		}
	}
	n.Lock()
	removed := n.removeStaleIPs(names, &alive)
	require.Empty(t, n.removeStaleIPs(names, &alive))
	n.Unlock()
	require.Len(t, removed, nameCount*2/3)
	require.Len(t, n.cache.names(), nameCount)
	for i := range nameCount {
		name := fmt.Sprintf("name-%d.example.", i)
		switch i % 3 {
		case 0:
			require.NotContains(t, removed, name)
			require.ElementsMatch(t, ips, n.cache.lookup(name))
		case 1:
			require.True(t, removed[name].Equal(set.NewSet(ips[2])))
			require.ElementsMatch(t, ips[:2], n.cache.lookup(name))
		case 2:
			require.True(t, removed[name].Equal(set.NewSet(ips[1:]...)))
			require.Equal(t, ips[:1], n.cache.lookup(name))
		}
	}
}
