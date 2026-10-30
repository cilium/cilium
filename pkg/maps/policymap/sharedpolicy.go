// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"iter"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// ErrSharedPolicyMapFull is returned when an endpoint's policy does not fit in the shared
// policy map.
var ErrSharedPolicyMapFull = errors.New("shared policy map is full")

func (f *factory) SharedPolicyEnabled() bool {
	return f != nil && f.allocator != nil
}

// SyncEndpointOverlay syncs the policy rules for the given endpoint into the shared LPM trie
// and updates the overlay map. On failure, e.g. when the shared policy map is full, the
// endpoint keeps its current rule set.
func (f *factory) SyncEndpointOverlay(epID uint16, entries iter.Seq2[policyTypes.Key, policyTypes.MapStateEntry]) error {
	if f.allocator == nil {
		return nil
	}

	var sharedRules []ruleWithEntry
	for key, entry := range entries {
		sharedRules = append(sharedRules, ruleWithEntry{
			Key:   key,
			Entry: entry,
		})
	}

	// Update shared rules and their endpoint references together.
	_, _, err := f.updateEndpointRules(epID, sharedRules)
	if errors.Is(err, unix.ENOSPC) {
		return fmt.Errorf("failed to update rule set: %w (see --%s): %w", ErrSharedPolicyMapFull, PolicySharedMapMaxName, err)
	}
	if err != nil {
		return fmt.Errorf("failed to update rule set: %w", err)
	}

	return nil
}

// LockdownEndpoint makes the datapath deny all traffic of the endpoint, by pointing its
// overlay entry to lockdownRuleSetID, and releases its rule set. The endpoint gets a rule set
// again on its next successful SyncEndpointOverlay.
func (f *factory) LockdownEndpoint(epID uint16) error {
	if f.allocator == nil {
		return nil
	}

	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()

	// Update the overlay entry first, so that the datapath never uses a rule set that is
	// being deleted.
	if err := f.updateOverlayPolicyEntryLocked(epID, lockdownRuleSetID); err != nil {
		return fmt.Errorf("failed to update policy overlay entry: %w", err)
	}
	if ruleSetID, ok := a.epToRuleSetID[epID]; ok {
		delete(a.epToRuleSetID, epID)
		f.releaseRuleSetLocked(ruleSetID)
	}
	return nil
}

// removeEndpointOverlay removes the endpoint's overlay entry and its reference to its rule
// set. The overlay entry is deleted first, so that the datapath never uses a rule set that is
// being deleted, and an agent restart in between only leaves behind an unused rule set, which
// is deleted on restore.
func (f *factory) removeEndpointOverlay(epID uint16) error {
	if f.allocator == nil {
		return nil
	}

	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()

	f.deletePendingRuleSetsLocked()

	err := f.overlayMap.Delete(&OverlayKey{EndpointID: uint32(epID)})
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed to delete policy overlay entry: %w", err)
	}
	if ruleSetID, ok := a.epToRuleSetID[epID]; ok {
		delete(a.epToRuleSetID, epID)
		f.releaseRuleSetLocked(ruleSetID)
	}
	return nil
}

// restoreSharedPolicyState restores the shared policy state from the pinned maps on agent
// start, so that the datapath keeps enforcing each endpoint's policy until the endpoint is
// regenerated. Its current policy is then synced against the restored entries of its rule set
// (see SyncEndpointOverlay). Rule sets that no endpoint uses are left over from an agent
// restart while switching an endpoint to another rule set, and are deleted. Overlay entries
// of endpoints that no longer exist are removed once the endpoints have been restored (see
// RemoveStaleEndpointOverlays).
func (f *factory) restoreSharedPolicyState() error {
	if f.allocator == nil {
		return nil
	}

	var errs error

	// The rule set of each endpoint.
	endpoints := make(map[uint16]uint32)
	err := f.overlayMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*OverlayKey)
		val, okV := v.(*OverlayValue)
		if !okK || !okV {
			errs = errors.Join(errs, fmt.Errorf("unexpected policy overlay map entry %T: %T", k, v))
			return
		}
		// Endpoints in lockdown point to lockdownRuleSetID, which has no rule set.
		if val.RuleSetID != lockdownRuleSetID {
			endpoints[uint16(key.EndpointID)] = val.RuleSetID
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump policy overlay map during recovery: %w", err)
	}

	// The entries of each rule set.
	ruleSets := make(map[uint32][]sharedRule)
	err = f.sharedMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*SharedPolicyKey)
		val, okV := v.(*PolicyEntry)
		if !okK || !okV {
			errs = errors.Join(errs, fmt.Errorf("unexpected shared policy map entry %T: %T", k, v))
			return
		}
		if key.RuleSetID != lockdownRuleSetID {
			ruleSets[key.RuleSetID] = append(ruleSets[key.RuleSetID], sharedRule{Key: *key, Entry: *val})
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump shared policy map during recovery: %w", err)
	}
	if errs != nil {
		return errs
	}

	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()

	for id, rules := range ruleSets {
		a.byID[id] = &ruleSetEntry{rules: rules}
		a.nextRuleSetID = max(a.nextRuleSetID, id+1)
	}
	for epID, id := range endpoints {
		entry := a.byID[id]
		if entry == nil {
			// A rule set without entries, i.e. an empty policy.
			entry = &ruleSetEntry{}
			a.byID[id] = entry
			a.nextRuleSetID = max(a.nextRuleSetID, id+1)
		}
		entry.refcount++
		a.epToRuleSetID[epID] = id
	}
	for id, entry := range a.byID {
		if entry.refcount == 0 {
			f.deleteRuleSetLocked(id, entry)
			continue
		}
		a.setRulesLocked(id, entry, entry.rules, computeRuleSetHashFromSharedRules(entry.rules))
	}

	return nil
}

// DumpEndpointSharedEntries returns the realized shared policy map entries of the rule set
// currently assigned to the given endpoint in the overlay map, converted to the per-endpoint
// PolicyEntriesDump format. Returns nil if the endpoint has no overlay entry.
func (f *factory) DumpEndpointSharedEntries(epID uint16) (PolicyEntriesDump, error) {
	if f.allocator == nil {
		return nil, nil
	}

	v, err := f.overlayMap.Lookup(&OverlayKey{EndpointID: uint32(epID)})
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to look up overlay entry for endpoint %d: %w", epID, err)
	}
	overlay, ok := v.(*OverlayValue)
	if !ok {
		return nil, fmt.Errorf("unexpected overlay value type %T", v)
	}

	return dumpSharedRuleSetEntries(f.sharedMap, overlay.RuleSetID)
}

// HasEndpointOverlay reports whether the endpoint has an overlay entry, i.e. whether the
// datapath enforces the endpoint's policy from the shared policy map. Without an overlay
// entry the datapath uses the endpoint's per-endpoint policy map.
func (f *factory) HasEndpointOverlay(epID uint16) bool {
	if f.allocator == nil {
		return false
	}
	_, err := f.overlayMap.Lookup(&OverlayKey{EndpointID: uint32(epID)})
	return err == nil
}

// RemoveStaleEndpointOverlays removes the overlay entries and rule set references of
// endpoints for which 'exists' returns false, e.g. endpoints that were deleted while the
// agent was down. This is the shared policy map equivalent of removing the per-endpoint
// policy maps of such endpoints, so that an endpoint reusing the ID never sees the policy
// of the old endpoint.
func (f *factory) RemoveStaleEndpointOverlays(exists func(epID uint16) bool) error {
	if f.allocator == nil {
		return nil
	}

	var stale []uint16
	err := f.overlayMap.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		if key, ok := k.(*OverlayKey); ok && !exists(uint16(key.EndpointID)) {
			stale = append(stale, uint16(key.EndpointID))
		}
	})
	if err != nil {
		return fmt.Errorf("failed to dump policy overlay map: %w", err)
	}
	var errs error
	for _, epID := range stale {
		errs = errors.Join(errs, f.removeEndpointOverlay(epID))
	}
	return errs
}

func (f *factory) registerSharedPolicy(lifecycle cell.Lifecycle, reg *registry.MapRegistry) {
	f.allocator = NewRuleSetAllocator()
	var shared, overlay *bpf.Map
	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			var err error
			shared, err = bpf.NewMapFromRegistry(reg, SharedPolicyMapName, &SharedPolicyKey{}, &PolicyEntry{})
			if err != nil {
				return fmt.Errorf("create shared policy map: %w", err)
			}
			overlay, err = bpf.NewMapFromRegistry(reg, PolicyOverlayMapName, &OverlayKey{}, &OverlayValue{})
			if err != nil {
				return fmt.Errorf("create policy overlay map: %w", err)
			}
			if err := shared.OpenOrCreate(); err != nil {
				return fmt.Errorf("open shared policy map: %w", err)
			}
			if err := overlay.OpenOrCreate(); err != nil {
				return errors.Join(fmt.Errorf("open policy overlay map: %w", err), shared.Close())
			}
			f.sharedMap, f.overlayMap = shared, overlay
			f.allocator = NewRuleSetAllocator()

			f.logger.Info("Recovering shared policy state")
			if err := f.restoreSharedPolicyState(); err != nil {
				return errors.Join(err, overlay.Close(), shared.Close())
			}
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return errors.Join(overlay.Close(), shared.Close())
		},
	})
}
