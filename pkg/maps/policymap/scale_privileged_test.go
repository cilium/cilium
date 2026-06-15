// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"iter"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
)

func setupPrivilegedCommon(tb testing.TB) {
	testutils.PrivilegedTest(tb)

	logger := hivetest.Logger(tb)
	bpf.CheckOrMountFS(logger, "")

	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatal(err)
	}
}

func setupSharedMaps(tb testing.TB) {
	logger := hivetest.Logger(tb)
	// Make sure maps are clean
	_ = os.Remove(bpf.MapPath(logger, SharedPolicyMapName))
	_ = os.Remove(bpf.MapPath(logger, PolicyOverlayMapName))

	// OpenOrCreate maps
	err := SharedPolicyMap.OpenOrCreate()
	require.NoError(tb, err)
	err = PolicyOverlayMap.OpenOrCreate()
	require.NoError(tb, err)
}

func arenaRulesToSeq2(rules []ArenaRuleWithEntry) iter.Seq2[policytypes.Key, policytypes.MapStateEntry] {
	return func(yield func(policytypes.Key, policytypes.MapStateEntry) bool) {
		for _, r := range rules {
			if !yield(r.Key, r.Entry) {
				return
			}
		}
	}
}

func BenchmarkPrivilegedScaleUpdateShared(b *testing.B) {
	setupPrivilegedCommon(b)
	setupSharedMaps(b)
	defer func() {
		SharedPolicyMap.Close()
		PolicyOverlayMap.Close()
	}()

	option.Config.EnableSharedPolicy = true
	defer func() { option.Config.EnableSharedPolicy = false }()

	for _, sc := range scaleScenarios() {
		b.Run(sc.String(), func(b *testing.B) {
			rng := rand.New(rand.NewPCG(42, 100))
			baseRules := generateRules(rng, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			seq := arenaRulesToSeq2(baseRules)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for epID := 0; epID < sc.endpoints; epID++ {
					_, err := SyncEndpointOverlay(uint16(epID), seq, true, true)
					require.NoError(b, err)
				}
			}
		})
	}
}

func BenchmarkPrivilegedScaleUpdateLegacy(b *testing.B) {
	setupPrivilegedCommon(b)
	logger := hivetest.Logger(b)

	stats, err := createStatsMapForTest(testMapSize)
	require.NoError(b, err)
	defer stats.Close()

	for _, sc := range scaleScenarios() {
		b.Run(sc.String(), func(b *testing.B) {
			rng := rand.New(rand.NewPCG(42, 100))
			baseRules := generateRules(rng, sc.rulesPerPolicy, sc.identityRange, sc.portRange)

			// Pre-create maps to simulate existing endpoints
			var maps []*policyMap
			for epID := 0; epID < sc.endpoints; epID++ {
				m, err := newPolicyMap(logger, uint16(epID), testMapSize, stats)
				require.NoError(b, err)
				err = m.CreateUnpinned()
				require.NoError(b, err)
				maps = append(maps, m)

				localEpID := uint16(epID)
				b.Cleanup(func() {
					m.DeleteAll()
					m.Close()
					os.RemoveAll(bpf.LocalMapPath(logger, MapName, localEpID))
				})
			}

			// Convert base rules to policymap keys/entries
			type rulePair struct {
				Key   PolicyKey
				Entry PolicyEntry
			}
			var legacyRules []rulePair
			for _, r := range baseRules {
				key := NewKeyFromPolicyKey(r.Key)
				entry := NewEntryFromPolicyEntry(key, r.Entry)
				legacyRules = append(legacyRules, rulePair{Key: key, Entry: entry})
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, m := range maps {
					for _, r := range legacyRules {
						err := m.Update(&r.Key, &r.Entry)
						require.NoError(b, err)
					}
				}
			}
		})
	}
}
