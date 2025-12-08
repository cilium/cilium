// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"cmp"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/types"
)

type candidate struct {
	key         types.Key
	entry       types.MapStateEntry
	sharedEntry PolicyEntry
	isPrivate   bool
}

// sharedManager is a lightweight controller that consumes the existing policy
// map state and mirrors it into in-memory shared metadata plus overlay records.
// This intentionally avoids any datapath wiring until the layered policy map
// datapath pieces are enabled, but keeps the control-plane flow exercised when
// the feature gate is on.
type sharedManager struct {
	overlays map[uint16]OverlayEntryBPF

	spilloverCounts map[uint16]int    // Tracks spillover count per endpoint for metrics
	ruleSetIDs      map[uint16]uint32 // Tracks RuleSetID per endpoint
	allocator       *RuleSetAllocator
	maxShared       int
	maxPrivate      int

	mu sync.Mutex
}

var (
	sharedMgrOnce sync.Once
	sharedMgr     *sharedManager
)

// SharedManagerEnabled reports whether the layered shared policy map plumbing
// should be exercised based on the configured mode.
func SharedManagerEnabled() bool {
	return option.Config.EnablePolicySharedMapArena
}

// getSharedManager returns a process-wide shared manager, initializing it from
// the current configuration on first use. Callers should gate invocations with
// SharedManagerEnabled() to avoid unnecessary work when the feature is disabled.
func getSharedManager() *sharedManager {
	sharedMgrOnce.Do(func() {
		sharedMgr = &sharedManager{
			overlays:        make(map[uint16]OverlayEntryBPF),
			spilloverCounts: make(map[uint16]int),
			ruleSetIDs:      make(map[uint16]uint32),
		}
		poolSize := option.Config.PolicySharedMapRuleSetPoolSize
		if poolSize <= 0 {
			poolSize = defaults.PolicySharedMapRuleSetPoolSize
		}

		// Initialize Allocators

		var arenaAlloc *ArenaAllocator
		if option.Config.EnablePolicySharedMapArena {
			// Arena Map should be initialized by InitUniversalMaps
			m := ArenaMap()
			if m != nil {
				// Use Slog for Arena (new component)
				slogger := logging.DefaultSlogLogger.With(logfields.LogSubsys, "policymap-arena")
				alloc, err := NewArenaAllocator(slogger, m)
				if err != nil {
					logrus.WithError(err).Error("Failed to initialize Arena Allocator")
				} else {
					arenaAlloc = alloc
					logrus.Infof("Initialized Arena Allocator with max pages: %d", m.MaxEntries())
				}
			} else {
				logrus.Warn("EnableBPFArenaPolicy is true but Arena Map is not initialized (check InitUniversalMaps logic)")
			}
		}

		sharedMgr.allocator = NewRuleSetAllocator(poolSize, arenaAlloc)
		sharedMgr.maxShared = option.Config.PolicySharedMapMaxSharedRefs
		sharedMgr.maxPrivate = option.Config.PolicySharedMapMaxPrivateOverrides

		if sharedMgr.maxShared <= 0 {
			sharedMgr.maxShared = DefaultMaxSharedRefs
		}
		if sharedMgr.maxPrivate <= 0 {
			sharedMgr.maxPrivate = DefaultMaxPrivateOverride
		}
	})

	return sharedMgr
}

// WITHOUT an overlay entry, BPF lookups fail immediately with DROP_POLICY.
//
// When policy is disabled (both ingressPolicyEnabled and egressPolicyEnabled are false),
// a wildcard allow-all rule is added to ensure traffic is allowed. This matches the
// legacy mode behavior where policy-disabled endpoints allow all traffic.
func SyncEndpointOverlay(epID uint16, entries iter.Seq2[types.Key, types.MapStateEntry], ingressPolicyEnabled, egressPolicyEnabled bool) (map[types.Key]struct{}, error) {
	if !SharedManagerEnabled() {
		return nil, nil
	}

	mgr := getSharedManager()

	var candidates []candidate

	if entries != nil {
		entries(func(key types.Key, entry types.MapStateEntry) bool {
			// All rules are candidates for the arena in Phase 4.
			// LPM trie in BPF handles Deny/L7 precedence correctly.
			isPrivate := false

			pk := NewKeyFromPolicyKey(key)
			pe := NewEntryFromPolicyEntry(pk, entry)

			candidates = append(candidates, candidate{
				key:         key,
				entry:       entry,
				sharedEntry: pe,
				isPrivate:   isPrivate,
			})
			return true
		})
	}

	// When policy is disabled for a direction, add a wildcard allow-all rule.
	// This ensures that endpoints with policy disabled allow all traffic,
	// matching legacy mode behavior.
	if !ingressPolicyEnabled {
		wildcardKey := types.IngressKey() // Identity=0, Proto=0, Port=0, Direction=Ingress
		wildcardEntry := types.MapStateEntry{}
		pk := NewKeyFromPolicyKey(wildcardKey)
		pe := NewEntryFromPolicyEntry(pk, wildcardEntry)
		candidates = append(candidates, candidate{
			key:         wildcardKey,
			entry:       wildcardEntry,
			sharedEntry: pe,
			isPrivate:   false,
		})
	}
	if !egressPolicyEnabled {
		wildcardKey := types.EgressKey() // Identity=0, Proto=0, Port=0, Direction=Egress
		wildcardEntry := types.MapStateEntry{}
		pk := NewKeyFromPolicyKey(wildcardKey)
		pe := NewEntryFromPolicyEntry(pk, wildcardEntry)
		candidates = append(candidates, candidate{
			key:         wildcardKey,
			entry:       wildcardEntry,
			sharedEntry: pe,
			isPrivate:   false,
		})
	}

	sortCandidates(candidates)

	var sharedRules []ArenaRuleWithEntry
	for _, c := range candidates {
		if !c.isPrivate {
			sharedRules = append(sharedRules, ArenaRuleWithEntry{
				Key:   c.key,
				Entry: c.entry,
			})
		}
	}

	// Use incremental update when possible (Phase 1 optimization)
	// This will:
	// 1. Reuse existing RuleSetID if hash matches (fastest)
	// 2. Update in-place if endpoint is sole owner (incremental)
	// 3. Allocate new RuleSetID otherwise (fallback)
	groupID, wasIncremental, err := mgr.allocator.UpdateEndpointRules(epID, sharedRules)
	if err != nil {
		return nil, fmt.Errorf("failed to update rule set: %w", err)
	}

	// Track incremental vs full policy update metrics
	if option.Config.PolicySharedMapMetrics {
		if wasIncremental {
			metrics.PolicySharedMapOps.WithLabelValues("incremental_update", metrics.LabelValueOutcomeSuccess).Inc()
		} else {
			metrics.PolicySharedMapOps.WithLabelValues("full_update", metrics.LabelValueOutcomeSuccess).Inc()
		}
	}

	offloaded := make(map[types.Key]struct{}, len(candidates))
	var finalPrivateOverrides []OverlayPrivateEntry
	currentPrivateCount := 0
	currentSpilloverCount := 0

	for _, c := range candidates {
		if c.isPrivate {
			if currentPrivateCount < mgr.maxPrivate {
				pk := NewKeyFromPolicyKey(c.key)
				finalPrivateOverrides = append(finalPrivateOverrides, OverlayPrivateEntry{
					Key:   pk,
					Entry: c.sharedEntry,
				})
				currentPrivateCount++
				offloaded[c.key] = struct{}{}
			} else {
				currentSpilloverCount++
			}
		} else {
			// Shared entries are always marked offloaded as they are in the arena block
			offloaded[c.key] = struct{}{}
		}
	}

	var finalSharedHandles []uint32
	if groupID > 0 {
		finalSharedHandles = append(finalSharedHandles, groupID)
	}

	overlay := OverlayEntry{
		SharedHandles: finalSharedHandles,
		Private:       finalPrivateOverrides,
	}

	clamped := overlay.ClampWith(mgr.maxShared, mgr.maxPrivate)

	mgr.mu.Lock()
	old, ok := mgr.overlays[epID]
	var oldPrivate int
	if ok {
		oldPrivate = int(old.PrivateCount)
	}
	newPrivate := int(clamped.PrivateCount)
	if option.Config.PolicySharedMapMetrics {
		metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapPriv).Add(float64(newPrivate - oldPrivate))
	}

	oldSpill := mgr.spilloverCounts[epID]
	if option.Config.PolicySharedMapMetrics {
		metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapSpillover).Add(float64(currentSpilloverCount - oldSpill))
	}
	mgr.spilloverCounts[epID] = currentSpilloverCount

	// Note: refcount management is now handled internally by UpdateEndpointRules
	mgr.ruleSetIDs[epID] = groupID

	mgr.overlays[epID] = clamped
	mgr.mu.Unlock()

	if err := updateOverlayPolicyEntry(epID, clamped); err != nil {
		logrus.WithField(logfields.EndpointID, epID).WithError(err).Warn("failed to update overlay policy entry")
	}

	logrus.WithFields(logrus.Fields{
		logfields.EndpointID: epID,
		"offloaded":          len(offloaded),
		"sharedRefCount":     clamped.SharedRefCount,
		"privateCount":       clamped.PrivateCount,
	}).Info("Synced shared policy overlay")

	return offloaded, nil
}

// RestoreEndpointOverlay re-registers an existing overlay and its shared handles.
// This is used during agent restart to recover the state of the shared allocator.
func RestoreEndpointOverlay(epID uint16, overlay OverlayEntryBPF) {
	if !SharedManagerEnabled() {
		return
	}

	mgr := getSharedManager()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	// 1. Store the overlay
	mgr.overlays[epID] = overlay

	// 2. Restore references in allocator
	for i := 0; i < int(overlay.SharedRefCount); i++ {
		handle := overlay.SharedRefs[i]
		if handle > 0 {
			if err := mgr.allocator.RestoreRuleSet(handle); err != nil {
				logrus.WithFields(logrus.Fields{
					logfields.EndpointID: epID,
					"handle":             handle,
				}).WithError(err).Warn("failed to restore rule set reference during startup")
			} else {
				mgr.allocator.LinkEndpoint(epID, handle)
			}
			// Map endpoint to its RuleSetID (assuming 1 shared ref per EP in Phase 4)
			mgr.ruleSetIDs[epID] = handle
		}
	}
}

// RemoveEndpointOverlay drops overlay metadata and dereferences shared handles
// for the given endpoint. This allows endpoint teardown paths to keep the shared
// store accurate even before datapath garbage collection is wired up.
func RemoveEndpointOverlay(epID uint16) {
	if !SharedManagerEnabled() {
		return
	}

	mgr := getSharedManager()
	mgr.mu.Lock()
	overlay, ok := mgr.overlays[epID]
	if ok {
		delete(mgr.overlays, epID)
		if option.Config.PolicySharedMapMetrics {
			metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapPriv).Sub(float64(overlay.PrivateCount))
		}
	}
	oldSpill, spillOk := mgr.spilloverCounts[epID]
	if spillOk {
		delete(mgr.spilloverCounts, epID)
		if option.Config.PolicySharedMapMetrics {
			metrics.PolicySharedMapEntries.WithLabelValues(metrics.LabelSharedMapSpillover).Sub(float64(oldSpill))
		}
	}
	// Release RuleSetID (now uses allocator's internal endpoint tracking)
	delete(mgr.ruleSetIDs, epID)
	mgr.mu.Unlock()

	// Let allocator handle refcount and cleanup
	mgr.allocator.RemoveEndpoint(epID)

	if !ok {
		return
	}

	if err := deleteOverlayPolicyEntry(epID); err != nil {
		logrus.WithField(logfields.LogSubsys, "policymap").WithError(err).Debug("failed to delete overlay policy entry")
	}
}

// OverlaySnapshot returns a copy of the stored overlay entry for tests.
func OverlaySnapshot(epID uint16) (OverlayEntryBPF, bool) {
	mgr := getSharedManager()
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	overlay, ok := mgr.overlays[epID]
	return overlay, ok
}

// sortCandidates sorts candidates by (identity, direction, protocol, port).
// Uses slices.SortFunc (pdqsort) which is faster than sort.Slice for
// mostly-sorted or patterned inputs common in policy updates.
func sortCandidates(c []candidate) {
	slices.SortFunc(c, func(a, b candidate) int {
		if v := cmp.Compare(a.key.Identity, b.key.Identity); v != 0 {
			return v
		}
		if v := cmp.Compare(a.key.TrafficDirection(), b.key.TrafficDirection()); v != 0 {
			return v
		}
		if v := cmp.Compare(a.key.Nexthdr, b.key.Nexthdr); v != 0 {
			return v
		}
		return cmp.Compare(a.key.DestPort, b.key.DestPort)
	})
}
