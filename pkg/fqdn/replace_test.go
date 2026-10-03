// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/time"
)

// ReplaceFromCacheByNames must only restore (ip, name) pairs that were already
// present before the expiry. GC must never introduce a mapping the DNS path has
// not seen, because the DNS path is what waits for ipcache propagation.
func TestReplaceFromCacheByNamesOnlyRestoresKnownPairs(t *testing.T) {
	var (
		ip1 = netip.MustParseAddr("10.0.0.1")
		ip2 = netip.MustParseAddr("10.0.0.2")
		now = time.Now()
	)

	t.Run("known pair is restored", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		global.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)
		ep.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)

		global.ReplaceFromCacheByNames([]string{"a.example.com"}, ep)
		require.Equal(t, []netip.Addr{ip1}, global.Lookup("a.example.com"))
	})

	t.Run("unknown pair is not introduced", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		global.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)
		ep.Update(now, "a.example.com", []netip.Addr{ip1, ip2}, 3600)

		global.ReplaceFromCacheByNames([]string{"a.example.com"}, ep)
		require.Equal(t, []netip.Addr{ip1}, global.Lookup("a.example.com"),
			"ip2 was never in the global cache and must not be added by GC")
	})

	// Membership must be tested per (ip, name) pair, not per IP: testing only
	// whether the IP is known would wrongly restore this pair.
	t.Run("known IP under a different name is not introduced", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		global.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)
		global.Update(now, "b.example.com", []netip.Addr{ip2}, 3600)
		ep.Update(now, "a.example.com", []netip.Addr{ip1, ip2}, 3600)

		global.ReplaceFromCacheByNames([]string{"a.example.com"}, ep)
		require.Equal(t, []netip.Addr{ip1}, global.Lookup("a.example.com"),
			"ip2 is known, but not for this name, so it must not be restored")
		require.ElementsMatch(t, []string{"b.example.com"}, global.LookupIP(ip2))
	})

	t.Run("name absent from the endpoint cache is dropped", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		global.Update(now, "gone.example.com", []netip.Addr{ip1}, 3600)

		global.ReplaceFromCacheByNames([]string{"gone.example.com"}, ep)
		require.Empty(t, global.Lookup("gone.example.com"))
	})

	t.Run("names outside namesToUpdate are untouched", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		global.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)
		global.Update(now, "keep.example.com", []netip.Addr{ip2}, 3600)

		global.ReplaceFromCacheByNames([]string{"a.example.com"}, ep)
		require.Equal(t, []netip.Addr{ip2}, global.Lookup("keep.example.com"))
	})

	t.Run("many names on one IP all restore", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		names := []string{"a.example.com", "b.example.com", "c.example.com"}
		for _, n := range names {
			global.Update(now, n, []netip.Addr{ip1}, 3600)
			ep.Update(now, n, []netip.Addr{ip1}, 3600)
		}

		global.ReplaceFromCacheByNames(names, ep)
		for _, n := range names {
			require.Equal(t, []netip.Addr{ip1}, global.Lookup(n), "name %s", n)
		}
		require.ElementsMatch(t, names, global.LookupIP(ip1))
	})

	t.Run("returned snapshot describes the pre-expiry state", func(t *testing.T) {
		global, ep := NewDNSCache(0), NewDNSCache(0)
		global.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)
		ep.Update(now, "a.example.com", []netip.Addr{ip1}, 3600)

		old := global.ReplaceFromCacheByNames([]string{"a.example.com"}, ep)
		require.Contains(t, old, ip1)
		require.Contains(t, old[ip1], "a.example.com")
	})
}
