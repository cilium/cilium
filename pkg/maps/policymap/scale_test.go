// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type scaleConfig struct {
	endpoints      int
	rulesPerPolicy int
	uniquePolicies int
	identityRange  int
	portRange      int
}

func (sc scaleConfig) String() string {
	return fmt.Sprintf("ep%d_rules%d_uniq%d", sc.endpoints, sc.rulesPerPolicy, sc.uniquePolicies)
}

func scaleScenarios() []scaleConfig {
	return []scaleConfig{
		{endpoints: 100, rulesPerPolicy: 10, uniquePolicies: 5, identityRange: 50, portRange: 20},
		{endpoints: 500, rulesPerPolicy: 20, uniquePolicies: 10, identityRange: 100, portRange: 50},
		{endpoints: 1000, rulesPerPolicy: 50, uniquePolicies: 20, identityRange: 200, portRange: 100},
		{endpoints: 2000, rulesPerPolicy: 100, uniquePolicies: 50, identityRange: 500, portRange: 200},
	}
}

func generateRules(rng *rand.Rand, numRules, identityRange, portRange int) []ArenaRuleWithEntry {
	rules := make([]ArenaRuleWithEntry, numRules)
	for i := range numRules {
		id := identity.NumericIdentity(rng.IntN(identityRange) + 1)
		port := uint16(rng.IntN(portRange) + 1)
		proto := u8proto.TCP
		if rng.Float32() < 0.2 {
			proto = u8proto.UDP
		}
		direction := trafficdirection.Ingress
		if rng.Float32() < 0.5 {
			direction = trafficdirection.Egress
		}

		key := policytypes.KeyForDirection(direction).
			WithIdentity(id).
			WithPortProto(proto, port)

		rules[i] = ArenaRuleWithEntry{
			Key:   key,
			Entry: policytypes.AllowEntry(),
		}
	}
	return rules
}

func BenchmarkScaleHashAndSort(b *testing.B) {
	for _, sc := range scaleScenarios() {
		b.Run(sc.String(), func(b *testing.B) {
			rng := rand.New(rand.NewPCG(42, 100))
			base := generateRules(rng, sc.rulesPerPolicy, sc.identityRange, sc.portRange)

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ComputeRuleSetHashFromEntries(base)
			}
		})
	}
}

func TestScaleAnalysisMemory(t *testing.T) {
	fmt.Println("\n=== SCALE ANALYSIS: Memory & Deduplication ===")
	fmt.Println("Comparing legacy per-endpoint maps vs shared policy LPM trie maps")
	fmt.Println()

	for _, sc := range scaleScenarios() {
		t.Run(sc.String(), func(t *testing.T) {
			// Legacy mode: each endpoint stores its own copy of all rules
			legacyEntries := sc.endpoints * sc.rulesPerPolicy
			legacyBytes := legacyEntries * 32 // ~32 bytes per map entry (key + entry)

			// Shared LPM mode: unique policies are shared, plus a small overlay per endpoint
			sharedEntries := sc.uniquePolicies * sc.rulesPerPolicy
			sharedBytes := sharedEntries * 24 // SharedPolicyKey(16) + PolicyEntry(8)
			overlayBytes := sc.endpoints * 16 // OverlayKey(8) + OverlayValue(8)
			totalSharedBytes := sharedBytes + overlayBytes

			savings := float64(legacyBytes-totalSharedBytes) / float64(legacyBytes) * 100
			dedupRatio := float64(legacyEntries) / float64(sharedEntries)

			fmt.Printf("--- %s ---\n", sc.String())
			fmt.Printf("  Endpoints:          %d\n", sc.endpoints)
			fmt.Printf("  Rules/policy:       %d\n", sc.rulesPerPolicy)
			fmt.Printf("  Unique policies:    %d\n", sc.uniquePolicies)
			fmt.Printf("  LEGACY MODE:\n")
			fmt.Printf("    Total BPF Entries:  %d\n", legacyEntries)
			fmt.Printf("    Estimated Memory:   %s\n", humanBytes(legacyBytes))
			fmt.Printf("    BPF Maps:           %d\n", sc.endpoints)
			fmt.Printf("  SHARED LPM MODE:\n")
			fmt.Printf("    Shared BPF Entries: %d (deduplication ratio: %.1fx)\n",
				sharedEntries, dedupRatio)
			fmt.Printf("    Memory (shared):    %s\n", humanBytes(sharedBytes))
			fmt.Printf("    Memory (overlay):   %s\n", humanBytes(overlayBytes))
			fmt.Printf("    Memory (total):     %s\n", humanBytes(totalSharedBytes))
			fmt.Printf("    BPF Maps:           2 (1 shared + 1 overlay)\n")
			fmt.Printf("  SAVINGS: %.1f%% memory reduction (%s saved)\n\n",
				savings, humanBytes(legacyBytes-totalSharedBytes))
		})
	}
}

func humanBytes(b int) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
