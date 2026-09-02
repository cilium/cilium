// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/time"
)

// TestZombieNameSetStaysInStepWithNames guards the de-duplication set against
// going stale. Names is also mutated outside Upsert, by ForceExpire and
// ForceExpireByNameIP. If a removed name were left behind in the set, Upsert
// would treat it as already present and silently refuse to re-add it, so the
// name would be lost from the zombie for good.
//
// Every case runs on both sides of nameSetThreshold. Below it no set is
// allocated at all, so a case built from a couple of names exercises none of
// this bookkeeping and on its own guards nothing.
func TestZombieNameSetStaysInStepWithNames(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	now := time.Now()

	for _, tc := range []struct {
		name   string
		filler int
	}{
		{"below threshold", 0},
		{"above threshold", nameSetThreshold},
	} {
		filler := make([]string, tc.filler)
		for i := range filler {
			filler[i] = fmt.Sprintf("filler%d.example.com", i)
		}

		// seed returns a zombie already holding the filler names, asserting that
		// the set is live exactly when the name count warrants it. Without that
		// check the "above threshold" run could silently stop covering the set.
		seed := func(t *testing.T) *DNSZombieMappings {
			z := NewDNSZombieMappings(hivetest.Logger(t),
				defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)
			if len(filler) > 0 {
				z.Upsert(now, ip, filler...)
				z.Lock()
				require.NotNil(t, z.deletes[ip].nameSet,
					"a zombie at or above nameSetThreshold must carry a set")
				z.Unlock()
			}
			return z
		}
		want := func(names ...string) []string {
			return append(append([]string{}, filler...), names...)
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Run("ForceExpireByNameIP then re-Upsert", func(t *testing.T) {
				z := seed(t)
				z.Upsert(now, ip, "a.example.com", "b.example.com")

				// A new set of A records for a.example.com clears just that name.
				z.ForceExpireByNameIP(time.Time{}, "a.example.com", ip)
				z.Lock()
				require.ElementsMatch(t, want("b.example.com"), z.deletes[ip].Names)
				z.Unlock()

				// a.example.com expires again and must come back.
				z.Upsert(now, ip, "a.example.com")
				z.Lock()
				require.ElementsMatch(t,
					want("b.example.com", "a.example.com"), z.deletes[ip].Names,
					"name removed by ForceExpireByNameIP must be re-addable")
				z.Unlock()
			})

			t.Run("ForceExpire then re-Upsert", func(t *testing.T) {
				z := seed(t)
				z.Upsert(now, ip, "drop.example.com", "keep.example.com")

				z.ForceExpire(time.Time{}, regexp.MustCompile(`^drop\.`))
				z.Lock()
				require.ElementsMatch(t, want("keep.example.com"), z.deletes[ip].Names)
				z.Unlock()

				z.Upsert(now, ip, "drop.example.com")
				z.Lock()
				require.ElementsMatch(t,
					want("keep.example.com", "drop.example.com"), z.deletes[ip].Names,
					"name removed by ForceExpire must be re-addable")
				z.Unlock()
			})

			t.Run("no duplicates after churn", func(t *testing.T) {
				z := seed(t)
				for range 5 {
					z.Upsert(now, ip, "a.example.com", "b.example.com")
					z.ForceExpireByNameIP(time.Time{}, "a.example.com", ip)
					z.Upsert(now, ip, "a.example.com")
				}
				z.Lock()
				require.ElementsMatch(t,
					want("a.example.com", "b.example.com"), z.deletes[ip].Names)
				z.Unlock()
			})
		})
	}
}

// ForceExpire passes a closure that records every name it removes, so
// removeNames must invoke the predicate exactly once per name. A slip such as
// re-testing the first match would silently duplicate those records.
func TestRemoveNamesCallsPredicateOncePerName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		names []string
		drop  map[string]bool
		want  []string
	}{
		{"no match", []string{"a", "b", "c"}, nil, []string{"a", "b", "c"}},
		{"first", []string{"a", "b", "c"}, map[string]bool{"a": true}, []string{"b", "c"}},
		{"middle", []string{"a", "b", "c"}, map[string]bool{"b": true}, []string{"a", "c"}},
		{"last", []string{"a", "b", "c"}, map[string]bool{"c": true}, []string{"a", "b"}},
		{"all", []string{"a", "b", "c"}, map[string]bool{"a": true, "b": true, "c": true}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zombie := &DNSZombieMapping{}
			zombie.addNames(tc.names...)

			var seen []string
			zombie.removeNames(func(n string) bool {
				seen = append(seen, n)
				return tc.drop[n]
			})

			require.Equal(t, tc.names, seen, "predicate must see every name exactly once, in order")
			if len(tc.want) == 0 {
				require.Empty(t, zombie.Names)
			} else {
				require.Equal(t, tc.want, zombie.Names)
			}

			// A removed name must be re-addable, i.e. nameSet did not go stale.
			for n := range tc.drop {
				before := len(zombie.Names)
				zombie.addNames(n)
				require.Len(t, zombie.Names, before+1, "removed name %q was not re-added", n)
			}
		})
	}
}

// The membership set is only allocated past nameSetThreshold, so a scenario
// built from a handful of names leaves nameSet nil and exercises none of the
// set bookkeeping. This covers the same churn above the threshold, where a name
// dropped from Names but left behind in nameSet would make a later re-Upsert of
// that name a silent no-op.
func TestZombieNameSetStaysInStepAboveThreshold(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	now := time.Now()
	const total = nameSetThreshold + 108

	z := NewDNSZombieMappings(hivetest.Logger(t),
		defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)
	for i := range total {
		z.Upsert(now, ip, fmt.Sprintf("n%d.example.com.", i))
	}

	// GC returns deep copies, which deliberately carry no set (it is rebuilt
	// lazily on demand), so the set itself has to be inspected on the live
	// zombie rather than on the copy.
	live := z.deletes[ip]
	require.NotNil(t, live.nameSet, "a zombie past the threshold must carry a set")
	require.Len(t, live.Names, total)

	// Remove a name, then add it back. If the set still claims to hold it, the
	// re-Upsert is skipped and the name is lost from Names for good.
	const victim = "n7.example.com."
	z.ForceExpireByNameIP(now, victim, ip)
	z.Upsert(now, ip, victim)

	alive, _ := z.GC()
	require.Len(t, alive, 1)
	require.Contains(t, alive[0].Names, victim, "a removed name must be re-addable")
	require.Len(t, alive[0].Names, total, "re-adding must not duplicate or drop names")
	require.Len(t, z.deletes[ip].nameSet, total, "the set must stay in step with Names")

	// Every name must still be individually removable, which fails if the set
	// and the slice have drifted apart.
	for i := range total {
		z.ForceExpireByNameIP(now, fmt.Sprintf("n%d.example.com.", i), ip)
	}
	alive, _ = z.GC()
	require.Empty(t, alive, "removing every name must drop the zombie entirely")
}

// Names is documented as being maintained de-duplicated, but addNames only
// guards the names it is asked to insert, so it cannot drop a duplicate that
// arrived with the list. Names is deserialized straight from the endpoint
// header file, which is not trusted to be unique, so the list is normalized
// once on restore instead.
//
// This runs on both sides of nameSetThreshold because the two are normalized by
// different code: below it by pkg/slices.Unique, at or above it by
// buildNameSet de-duplicating as it indexes.
func TestRestoredZombieNamesAreDeDuplicated(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")

	for _, tc := range []struct {
		name   string
		filler int
	}{
		{"below threshold", 0},
		{"above threshold", nameSetThreshold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			names := []string{"dup", "dup", "other"}
			for i := range tc.filler {
				names = append(names, fmt.Sprintf("filler%d.example.com", i))
			}
			encoded, err := json.Marshal(names)
			require.NoError(t, err)
			raw := fmt.Appendf(nil, `{"deletes":{"10.0.0.1":{"names":%s,`+
				`"ip":"10.0.0.1","delete-pending-at":"2100-01-01T00:00:00Z",`+
				`"alive-at":"2100-01-01T00:00:00Z"}}}`, encoded)

			z := NewDNSZombieMappings(hivetest.Logger(t),
				defaults.ToFQDNsMaxDeferredConnectionDeletes, defaults.ToFQDNsMaxIPsPerHost)
			require.NoError(t, json.Unmarshal(raw, z))

			z.Lock()
			got := z.deletes[ip]
			require.Len(t, got.Names, len(names)-1,
				"the duplicate present in the restored list must not survive")
			if tc.filler > 0 {
				require.NotNil(t, got.nameSet,
					"a restored zombie at or above nameSetThreshold must carry a set")
				require.Len(t, got.nameSet, len(got.Names),
					"the set must stay in step with the de-duplicated Names")
			}
			z.Unlock()

			// The de-duplicated name must still be removable in one step: a
			// second copy left in Names would outlive the removal.
			z.ForceExpireByNameIP(time.Time{}, "dup", ip)
			z.Lock()
			require.NotContains(t, z.deletes[ip].Names, "dup")
			z.Unlock()
		})
	}
}
