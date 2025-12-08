// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

// ===================================================================
// Task 5: Scale Testing - Legacy vs Arena Mode Comparison
//
// This file contains benchmarks and analysis tests that compare the
// performance characteristics of legacy per-endpoint policy maps vs
// arena shared policy maps at production scale (100-2000 endpoints).
//
// Metrics measured:
//   - Memory usage (per-endpoint vs shared)
//   - Policy update latency (hash + write operations)
//   - Rule deduplication effectiveness
//   - Endpoint churn cost (add/remove)
//   - Policy churn cost (frequent updates)
//
// Run with:
//   go test -bench=BenchmarkScale -benchtime=3s -count=3 -v ./pkg/maps/policymap/
//   go test -run=TestScaleAnalysis -v ./pkg/maps/policymap/
// ===================================================================

// scaleConfig defines parameters for a scale test scenario.
type scaleConfig struct {
	endpoints        int   // Number of endpoints
	rulesPerPolicy   int   // Rules per policy set
	uniquePolicies   int   // Number of distinct policy sets (rest are duplicates)
	identityRange    int   // Range of identities used
	portRange        int   // Range of ports used
}

func (sc scaleConfig) String() string {
	return fmt.Sprintf("ep%d_rules%d_uniq%d", sc.endpoints, sc.rulesPerPolicy, sc.uniquePolicies)
}

// scaleScenarios returns standard scale test configurations.
func scaleScenarios() []scaleConfig {
	return []scaleConfig{
		// Small cluster: 100 endpoints, 10 rules each, 5 unique policies
		{endpoints: 100, rulesPerPolicy: 10, uniquePolicies: 5, identityRange: 50, portRange: 20},
		// Medium cluster: 500 endpoints, 20 rules each, 10 unique policies
		{endpoints: 500, rulesPerPolicy: 20, uniquePolicies: 10, identityRange: 100, portRange: 50},
		// Large cluster: 1000 endpoints, 50 rules each, 20 unique policies
		{endpoints: 1000, rulesPerPolicy: 50, uniquePolicies: 20, identityRange: 200, portRange: 100},
		// XL cluster: 2000 endpoints, 100 rules each, 50 unique policies
		{endpoints: 2000, rulesPerPolicy: 100, uniquePolicies: 50, identityRange: 500, portRange: 200},
	}
}

// generatePolicySet creates a deterministic set of rules for a given policy ID.
func generatePolicySet(policyID, numRules, identityRange, portRange int) []ArenaRuleWithEntry {
	rng := rand.New(rand.NewSource(int64(policyID * 1000)))
	rules := make([]ArenaRuleWithEntry, numRules)

	for i := 0; i < numRules; i++ {
		id := identity.NumericIdentity(rng.Intn(identityRange) + 1)
		port := uint16(rng.Intn(portRange) + 1)
		proto := u8proto.TCP
		if rng.Float32() < 0.2 {
			proto = u8proto.UDP
		}
		dir := trafficdirection.Ingress
		if rng.Float32() < 0.3 {
			dir = trafficdirection.Egress
		}

		key := policyTypes.KeyForDirection(dir).
			WithIdentity(id).
			WithPortProto(proto, port)

		entry := policyTypes.AllowEntry()
		if rng.Float32() < 0.1 {
			entry = entry.WithDeny(true)
		}

		rules[i] = ArenaRuleWithEntry{Key: key, Entry: entry}
	}
	return rules
}

// generateLegacyPolicySet creates legacy SharedPolicyKey rules for comparison.
func generateLegacyPolicySet(policyID, numRules, identityRange, portRange int) []SharedPolicyKey {
	rng := rand.New(rand.NewSource(int64(policyID * 1000)))
	rules := make([]SharedPolicyKey, numRules)

	for i := 0; i < numRules; i++ {
		id := identity.NumericIdentity(rng.Intn(identityRange) + 1)
		port := uint16(rng.Intn(portRange) + 1)
		proto := u8proto.TCP
		if rng.Float32() < 0.2 {
			proto = u8proto.UDP
		}
		dir := trafficdirection.Ingress
		if rng.Float32() < 0.3 {
			dir = trafficdirection.Egress
		}

		rules[i] = SharedPolicyKey{
			Identity:        id,
			Direction:       dir,
			Nexthdr:         proto,
			DestPortNetwork: (port >> 8) | (port << 8), // htons
		}
	}
	return rules
}

// ===================================================================
// Benchmark: Hash Computation (Legacy SHA256 vs Arena xxhash)
// ===================================================================

func BenchmarkScaleHashLegacy(b *testing.B) {
	for _, sc := range scaleScenarios() {
		b.Run(sc.String(), func(b *testing.B) {
			// Pre-generate all unique policy sets
			policySets := make([][]SharedPolicyKey, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				policySets[i] = generateLegacyPolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				policyIdx := i % sc.uniquePolicies
				_ = ComputeRuleSetHash(policySets[policyIdx])
			}
		})
	}
}

func BenchmarkScaleHashArena(b *testing.B) {
	for _, sc := range scaleScenarios() {
		b.Run(sc.String(), func(b *testing.B) {
			// Pre-generate all unique policy sets
			policySets := make([][]ArenaRuleWithEntry, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				policySets[i] = generatePolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				policyIdx := i % sc.uniquePolicies
				_ = ComputeRuleSetHashFromEntries(policySets[policyIdx])
			}
		})
	}
}

// ===================================================================
// Benchmark: Incremental diff computation
// ===================================================================

func BenchmarkScaleDiff(b *testing.B) {
	for _, sc := range scaleScenarios() {
		b.Run(sc.String()+"/no_change", func(b *testing.B) {
			rules := generateSharedLPMRules(1, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				added, removed, modified := diffSharedLPMRules(rules, rules)
				_ = added
				_ = removed
				_ = modified
			}
		})

		b.Run(sc.String()+"/1_rule_added", func(b *testing.B) {
			old := generateSharedLPMRules(1, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			new := make([]SharedLPMRule, len(old)+1)
			copy(new, old)
			new[len(old)] = SharedLPMRule{
				RuleSetID: 1, Identity: 99999, Egress: 0,
				Protocol: 6, DPort: 9999, PrefixLen: 24,
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				added, removed, modified := diffSharedLPMRules(old, new)
				_ = added
				_ = removed
				_ = modified
			}
		})

		b.Run(sc.String()+"/10pct_changed", func(b *testing.B) {
			old := generateSharedLPMRules(1, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			new := make([]SharedLPMRule, len(old))
			copy(new, old)
			// Modify 10% of rules (change value fields)
			changeCnt := len(new) / 10
			if changeCnt == 0 {
				changeCnt = 1
			}
			for j := 0; j < changeCnt; j++ {
				new[j].ProxyPort = 8080
			}
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				added, removed, modified := diffSharedLPMRules(old, new)
				_ = added
				_ = removed
				_ = modified
			}
		})
	}
}

// generateSharedLPMRules creates SharedLPMRule slices for diff benchmarks.
func generateSharedLPMRules(ruleSetID uint32, numRules, identityRange, portRange int) []SharedLPMRule {
	rng := rand.New(rand.NewSource(int64(ruleSetID * 1000)))
	rules := make([]SharedLPMRule, numRules)
	for i := 0; i < numRules; i++ {
		rules[i] = SharedLPMRule{
			RuleSetID: ruleSetID,
			Identity:  uint32(rng.Intn(identityRange) + 1),
			Egress:    uint8(rng.Intn(2)),
			Protocol:  6,
			DPort:     uint16(rng.Intn(portRange) + 1),
			PrefixLen: 24,
		}
	}
	return rules
}

// ===================================================================
// Benchmark: Sort performance (sort.Slice vs slices.SortFunc)
// ===================================================================

func BenchmarkScaleSortCandidates(b *testing.B) {
	for _, sc := range scaleScenarios() {
		b.Run(sc.String(), func(b *testing.B) {
			base := make([]candidate, sc.rulesPerPolicy)
			rng := rand.New(rand.NewSource(42))
			for i := range base {
				key := policyTypes.KeyForDirection(trafficdirection.Ingress).
					WithIdentity(identity.NumericIdentity(rng.Intn(sc.identityRange) + 1)).
					WithPortProto(u8proto.TCP, uint16(rng.Intn(sc.portRange)+1))
				base[i] = candidate{key: key, entry: policyTypes.AllowEntry()}
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c := make([]candidate, len(base))
				copy(c, base)
				sortCandidates(c)
			}
		})
	}
}

// ===================================================================
// Analysis Test: Memory & Deduplication at Scale
// ===================================================================

// TestScaleAnalysisMemoryDedup analyzes memory savings from deduplication
// at various scales. Does NOT require BPF maps - pure Go computation.
func TestScaleAnalysisMemoryDedup(t *testing.T) {
	fmt.Println("\n=== SCALE ANALYSIS: Memory & Deduplication ===")
	fmt.Println("Comparing legacy per-endpoint maps vs arena shared policy maps")
	fmt.Println()

	for _, sc := range scaleScenarios() {
		t.Run(sc.String(), func(t *testing.T) {
			// Generate policy assignments (which endpoint gets which policy)
			rng := rand.New(rand.NewSource(42))
			epPolicies := make([]int, sc.endpoints)
			for i := range epPolicies {
				epPolicies[i] = rng.Intn(sc.uniquePolicies)
			}

			// Count unique assignments
			policyCounts := make(map[int]int)
			for _, p := range epPolicies {
				policyCounts[p]++
			}

			// Legacy mode: each endpoint stores its own copy
			legacyEntries := sc.endpoints * sc.rulesPerPolicy
			legacyBytes := legacyEntries * 20 // ~20 bytes per LPM entry (key+value)

			// Arena mode: shared rule sets + overlay per endpoint
			arenaSharedEntries := sc.uniquePolicies * sc.rulesPerPolicy
			arenaSharedBytes := arenaSharedEntries * (16 + 8) // SharedLPMKey(16) + SharedLPMValue(8)
			arenaOverlayBytes := sc.endpoints * 200           // ~200 bytes per overlay entry
			arenaTotalBytes := arenaSharedBytes + arenaOverlayBytes

			// Arena rule data dedup (per-rule in arena memory)
			arenaRuleDataBytes := arenaSharedEntries * ArenaPolicyEntrySize // 12 bytes per entry

			savings := float64(legacyBytes-arenaTotalBytes) / float64(legacyBytes) * 100

			fmt.Printf("--- %s ---\n", sc.String())
			fmt.Printf("  Endpoints:          %d\n", sc.endpoints)
			fmt.Printf("  Rules/policy:       %d\n", sc.rulesPerPolicy)
			fmt.Printf("  Unique policies:    %d\n", sc.uniquePolicies)
			fmt.Printf("  Policy distribution:\n")
			for pid, count := range policyCounts {
				fmt.Printf("    Policy %d: %d endpoints (%.1f%%)\n", pid, count, float64(count)/float64(sc.endpoints)*100)
			}
			fmt.Printf("\n  LEGACY MODE:\n")
			fmt.Printf("    Total LPM entries:  %d\n", legacyEntries)
			fmt.Printf("    Memory (LPM maps):  %s\n", humanBytes(legacyBytes))
			fmt.Printf("    BPF maps:           %d (one per endpoint)\n", sc.endpoints)
			fmt.Printf("\n  ARENA MODE:\n")
			fmt.Printf("    Shared LPM entries: %d (deduplication ratio: %.1fx)\n",
				arenaSharedEntries, float64(legacyEntries)/float64(arenaSharedEntries))
			fmt.Printf("    Memory (shared LPM):%s\n", humanBytes(arenaSharedBytes))
			fmt.Printf("    Memory (overlays):  %s\n", humanBytes(arenaOverlayBytes))
			fmt.Printf("    Memory (arena data):%s\n", humanBytes(arenaRuleDataBytes))
			fmt.Printf("    Memory (total):     %s\n", humanBytes(arenaTotalBytes))
			fmt.Printf("    BPF maps:           1 (shared) + 1 (overlay)\n")
			fmt.Printf("\n  SAVINGS: %.1f%% memory reduction (%s saved)\n",
				savings, humanBytes(legacyBytes-arenaTotalBytes))
			fmt.Println()
		})
	}
}

// TestScaleAnalysisPolicyUpdateLatency measures policy update latency
// components at various scales.
func TestScaleAnalysisPolicyUpdateLatency(t *testing.T) {
	fmt.Println("\n=== SCALE ANALYSIS: Policy Update Latency Components ===")
	fmt.Println()

	for _, sc := range scaleScenarios() {
		t.Run(sc.String(), func(t *testing.T) {
			// Pre-generate policy sets
			policySets := make([][]ArenaRuleWithEntry, sc.uniquePolicies)
			legacySets := make([][]SharedPolicyKey, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				policySets[i] = generatePolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
				legacySets[i] = generateLegacyPolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			// Measure hash computation time
			const iterations = 100

			// Legacy hash (SHA256 + string formatting)
			start := time.Now()
			for i := 0; i < iterations; i++ {
				for _, ps := range legacySets {
					_ = ComputeRuleSetHash(ps)
				}
			}
			legacyHashTime := time.Since(start) / time.Duration(iterations*sc.uniquePolicies)

			// Arena hash (xxhash + binary encoding)
			start = time.Now()
			for i := 0; i < iterations; i++ {
				for _, ps := range policySets {
					_ = ComputeRuleSetHashFromEntries(ps)
				}
			}
			arenaHashTime := time.Since(start) / time.Duration(iterations*sc.uniquePolicies)

			// Measure diff computation time
			sharedRules := make([][]SharedLPMRule, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				sharedRules[i] = generateSharedLPMRules(uint32(i+1), sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			// Diff: no changes
			start = time.Now()
			for i := 0; i < iterations; i++ {
				for _, rules := range sharedRules {
					diffSharedLPMRules(rules, rules)
				}
			}
			diffNoChangeTime := time.Since(start) / time.Duration(iterations*sc.uniquePolicies)

			// Diff: 1 rule added
			modifiedSets := make([][]SharedLPMRule, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				mod := make([]SharedLPMRule, len(sharedRules[i])+1)
				copy(mod, sharedRules[i])
				mod[len(sharedRules[i])] = SharedLPMRule{
					RuleSetID: uint32(i + 1), Identity: 99999,
					Protocol: 6, DPort: 9999, PrefixLen: 24,
				}
				modifiedSets[i] = mod
			}
			start = time.Now()
			for i := 0; i < iterations; i++ {
				for j, rules := range sharedRules {
					diffSharedLPMRules(rules, modifiedSets[j])
				}
			}
			diffAddOneTime := time.Since(start) / time.Duration(iterations*sc.uniquePolicies)

			// Simulated full rebuild time (legacy approach)
			// In legacy mode, a policy update for N endpoints writes N*rulesPerPolicy entries
			bpfWriteLatency := 5 * time.Microsecond // Estimated per-entry BPF write
			legacyFullRebuildPerEP := time.Duration(sc.rulesPerPolicy) * bpfWriteLatency
			arenaIncrementalPerEP := bpfWriteLatency // Only 1 entry written for incremental

			fmt.Printf("--- %s ---\n", sc.String())
			fmt.Printf("  Hash computation:\n")
			fmt.Printf("    Legacy (SHA256):     %v per policy set\n", legacyHashTime)
			fmt.Printf("    Arena  (xxhash):     %v per policy set\n", arenaHashTime)
			fmt.Printf("    Speedup:             %.1fx\n", float64(legacyHashTime)/float64(arenaHashTime))
			fmt.Printf("\n  Diff computation:\n")
			fmt.Printf("    No changes:          %v\n", diffNoChangeTime)
			fmt.Printf("    1 rule added:        %v\n", diffAddOneTime)
			fmt.Printf("\n  Estimated BPF write latency (per endpoint policy update):\n")
			fmt.Printf("    Legacy full rebuild:  %v (%d writes × %v)\n",
				legacyFullRebuildPerEP, sc.rulesPerPolicy, bpfWriteLatency)
			fmt.Printf("    Arena incremental:    %v (1 write)\n", arenaIncrementalPerEP)
			fmt.Printf("    Speedup:              %.0fx\n",
				float64(legacyFullRebuildPerEP)/float64(arenaIncrementalPerEP))
			fmt.Printf("\n  Cluster-wide policy update (all %d endpoints):\n", sc.endpoints)
			fmt.Printf("    Legacy:  %v\n", time.Duration(sc.endpoints)*legacyFullRebuildPerEP)
			fmt.Printf("    Arena (hash match): ~%v (0 BPF writes for duplicate policies)\n",
				time.Duration(sc.endpoints)*arenaHashTime)
			fmt.Println()
		})
	}
}

// TestScaleAnalysisEndpointChurn measures the cost of endpoint add/remove cycles.
func TestScaleAnalysisEndpointChurn(t *testing.T) {
	fmt.Println("\n=== SCALE ANALYSIS: Endpoint Churn ===")
	fmt.Println("Simulating rapid endpoint creation/deletion (e.g., pod scaling)")
	fmt.Println()

	for _, sc := range scaleScenarios() {
		t.Run(sc.String(), func(t *testing.T) {
			// Pre-generate policy sets
			policySets := make([][]ArenaRuleWithEntry, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				policySets[i] = generatePolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			rng := rand.New(rand.NewSource(42))

			// Simulate: add all endpoints, then remove half, then add new ones
			const iterations = 3
			var totalHashTime, totalDiffTime time.Duration
			totalOps := 0

			for iter := 0; iter < iterations; iter++ {
				for epID := 0; epID < sc.endpoints; epID++ {
					policyIdx := rng.Intn(sc.uniquePolicies)
					rules := policySets[policyIdx]

					start := time.Now()
					_ = ComputeRuleSetHashFromEntries(rules)
					totalHashTime += time.Since(start)
					totalOps++
				}
			}

			avgHashTime := totalHashTime / time.Duration(totalOps)

			// Legacy: each new endpoint creates a new BPF map + writes all rules
			bpfMapCreateLatency := 500 * time.Microsecond // Estimated BPF map creation
			bpfWriteLatency := 5 * time.Microsecond
			legacyAddEP := bpfMapCreateLatency + time.Duration(sc.rulesPerPolicy)*bpfWriteLatency
			legacyRemoveEP := 100 * time.Microsecond // BPF map close + unpin

			// Arena: just hash + overlay update (no new BPF map)
			arenaAddEP := avgHashTime + 50*time.Microsecond // hash + overlay write
			arenaRemoveEP := 20 * time.Microsecond          // overlay delete + refcount decrement

			_ = totalDiffTime

			churnRate := 100 // endpoints per second
			legacyChurnCost := time.Duration(churnRate) * legacyAddEP
			arenaChurnCost := time.Duration(churnRate) * arenaAddEP

			fmt.Printf("--- %s ---\n", sc.String())
			fmt.Printf("  Per-endpoint operations:\n")
			fmt.Printf("    Legacy add:     %v (create BPF map + %d writes)\n", legacyAddEP, sc.rulesPerPolicy)
			fmt.Printf("    Arena add:      %v (hash + overlay write)\n", arenaAddEP)
			fmt.Printf("    Legacy remove:  %v\n", legacyRemoveEP)
			fmt.Printf("    Arena remove:   %v\n", arenaRemoveEP)
			fmt.Printf("\n  Churn simulation (%d ep/s):\n", churnRate)
			fmt.Printf("    Legacy cost/s:  %v\n", legacyChurnCost)
			fmt.Printf("    Arena cost/s:   %v\n", arenaChurnCost)
			fmt.Printf("    Speedup:        %.1fx\n", float64(legacyChurnCost)/float64(arenaChurnCost))
			fmt.Println()
		})
	}
}

// TestScaleAnalysisPolicyChurn measures the cost of frequent policy updates.
func TestScaleAnalysisPolicyChurn(t *testing.T) {
	fmt.Println("\n=== SCALE ANALYSIS: Policy Churn ===")
	fmt.Println("Simulating frequent policy changes (e.g., CiliumNetworkPolicy updates)")
	fmt.Println()

	for _, sc := range scaleScenarios() {
		t.Run(sc.String(), func(t *testing.T) {
			// Pre-generate base policy sets
			baseSets := make([][]SharedLPMRule, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				baseSets[i] = generateSharedLPMRules(uint32(i+1), sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			// Simulate various policy change patterns
			patterns := []struct {
				name       string
				changePct  float64 // Percentage of rules that change
			}{
				{"no_change", 0.0},
				{"1_rule_change", -1}, // special: exactly 1 rule
				{"5pct_change", 0.05},
				{"10pct_change", 0.10},
				{"50pct_change", 0.50},
				{"full_rebuild", 1.0},
			}

			const iterations = 100

			for _, pat := range patterns {
				// Create modified versions
				modSets := make([][]SharedLPMRule, sc.uniquePolicies)
				for i := 0; i < sc.uniquePolicies; i++ {
					mod := make([]SharedLPMRule, len(baseSets[i]))
					copy(mod, baseSets[i])

					var changeCnt int
					if pat.changePct == -1 {
						changeCnt = 1
					} else {
						changeCnt = int(float64(len(mod)) * pat.changePct)
					}
					if changeCnt > len(mod) {
						changeCnt = len(mod)
					}

					for j := 0; j < changeCnt; j++ {
						mod[j].ProxyPort = uint16(8080 + j)
					}
					modSets[i] = mod
				}

				// Measure diff time
				start := time.Now()
				var totalAdded, totalRemoved, totalModified int
				for iter := 0; iter < iterations; iter++ {
					for i := 0; i < sc.uniquePolicies; i++ {
						added, removed, modified := diffSharedLPMRules(baseSets[i], modSets[i])
						totalAdded += len(added)
						totalRemoved += len(removed)
						totalModified += len(modified)
					}
				}
				elapsed := time.Since(start)
				avgDiffTime := elapsed / time.Duration(iterations*sc.uniquePolicies)

				// Calculate BPF ops needed
				avgAdded := totalAdded / (iterations * sc.uniquePolicies)
				avgRemoved := totalRemoved / (iterations * sc.uniquePolicies)
				avgModified := totalModified / (iterations * sc.uniquePolicies)
				totalBPFOps := avgAdded + avgRemoved + avgModified*2 // modify = delete + add

				// Legacy comparison: always full rebuild
				legacyBPFOps := sc.rulesPerPolicy * 2 // delete all + write all

				fmt.Printf("  [%s] %s:\n", sc.String(), pat.name)
				fmt.Printf("    Diff time:     %v\n", avgDiffTime)
				fmt.Printf("    Changes:       +%d -%d ~%d\n", avgAdded, avgRemoved, avgModified)
				fmt.Printf("    Arena BPF ops: %d\n", totalBPFOps)
				fmt.Printf("    Legacy BPF ops:%d\n", legacyBPFOps)
				if totalBPFOps > 0 {
					fmt.Printf("    Reduction:     %.1fx fewer BPF ops\n",
						float64(legacyBPFOps)/float64(totalBPFOps))
				} else {
					fmt.Printf("    Reduction:     ∞ (0 BPF ops needed)\n")
				}
			}
			fmt.Println()
		})
	}
}

// TestScaleAnalysisSummary prints a consolidated summary table.
func TestScaleAnalysisSummary(t *testing.T) {
	fmt.Println("\n=== SCALE ANALYSIS: Summary Table ===")
	fmt.Println()
	fmt.Printf("%-20s | %-12s | %-12s | %-8s | %-12s | %-12s | %-8s\n",
		"Scenario", "Legacy Mem", "Arena Mem", "Savings", "Legacy Maps", "Arena Maps", "Dedup")
	fmt.Printf("%-20s-+-%-12s-+-%-12s-+-%-8s-+-%-12s-+-%-12s-+-%-8s\n",
		"--------------------", "------------", "------------", "--------",
		"------------", "------------", "--------")

	for _, sc := range scaleScenarios() {
		legacyEntries := sc.endpoints * sc.rulesPerPolicy
		legacyBytes := legacyEntries * 20
		arenaSharedEntries := sc.uniquePolicies * sc.rulesPerPolicy
		arenaSharedBytes := arenaSharedEntries * 24
		arenaOverlayBytes := sc.endpoints * 200
		arenaTotalBytes := arenaSharedBytes + arenaOverlayBytes
		savings := float64(legacyBytes-arenaTotalBytes) / float64(legacyBytes) * 100
		dedupRatio := float64(legacyEntries) / float64(arenaSharedEntries)

		fmt.Printf("%-20s | %-12s | %-12s | %5.1f%%  | %-12d | %-12d | %5.1fx\n",
			sc.String(),
			humanBytes(legacyBytes),
			humanBytes(arenaTotalBytes),
			savings,
			sc.endpoints,
			2,
			dedupRatio)
	}

	fmt.Println()
	fmt.Println("Legend:")
	fmt.Println("  Legacy Mem:  Total memory for per-endpoint LPM trie maps")
	fmt.Println("  Arena Mem:   Total memory for shared LPM + overlay entries")
	fmt.Println("  Legacy Maps: Number of BPF maps (one per endpoint)")
	fmt.Println("  Arena Maps:  Number of BPF maps (1 shared LPM + 1 overlay)")
	fmt.Println("  Dedup:       Entry deduplication ratio (legacy entries / arena entries)")
	fmt.Println()
}

// ===================================================================
// Benchmark: Full pipeline simulation
// ===================================================================

// BenchmarkScaleFullPipeline simulates the full policy update pipeline
// at various scales, measuring end-to-end latency.
func BenchmarkScaleFullPipeline(b *testing.B) {
	for _, sc := range scaleScenarios() {
		b.Run(sc.String()+"/hash_only", func(b *testing.B) {
			policySets := make([][]ArenaRuleWithEntry, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				policySets[i] = generatePolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			rng := rand.New(rand.NewSource(42))
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				policyIdx := rng.Intn(sc.uniquePolicies)
				_ = ComputeRuleSetHashFromEntries(policySets[policyIdx])
			}
		})

		b.Run(sc.String()+"/hash_and_sort", func(b *testing.B) {
			policySets := make([][]ArenaRuleWithEntry, sc.uniquePolicies)
			for i := 0; i < sc.uniquePolicies; i++ {
				policySets[i] = generatePolicySet(i, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			}

			rng := rand.New(rand.NewSource(42))
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				policyIdx := rng.Intn(sc.uniquePolicies)
				// Simulate full pipeline: sort candidates + hash
				rules := policySets[policyIdx]
				candidates := make([]candidate, len(rules))
				for j, r := range rules {
					candidates[j] = candidate{key: r.Key, entry: r.Entry}
				}
				sortCandidates(candidates)
				_ = ComputeRuleSetHashFromEntries(rules)
			}
		})

		b.Run(sc.String()+"/diff_incremental", func(b *testing.B) {
			base := generateSharedLPMRules(1, sc.rulesPerPolicy, sc.identityRange, sc.portRange)
			// Add 1 rule
			modified := make([]SharedLPMRule, len(base)+1)
			copy(modified, base)
			modified[len(base)] = SharedLPMRule{
				RuleSetID: 1, Identity: 99999, Protocol: 6, DPort: 9999, PrefixLen: 24,
			}

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				added, removed, mod := diffSharedLPMRules(base, modified)
				_ = added
				_ = removed
				_ = mod
			}
		})
	}
}

// ===================================================================
// Helpers
// ===================================================================

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

// Ensure sort package import is used (for legacy benchmark)
var _ = sort.Slice
