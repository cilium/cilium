// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// sharedPolicySnapshot is the content of the shared policy map and the policy overlay map.
type sharedPolicySnapshot struct {
	// overlay is the rule set ID of each endpoint.
	overlay map[uint16]uint32
	shared  map[SharedPolicyKey]PolicyEntry
}

// snapshotSharedPolicy reads the policy overlay map and the shared policy map.
func (f *factory) snapshotSharedPolicy() (*sharedPolicySnapshot, error) {
	s := &sharedPolicySnapshot{
		overlay: make(map[uint16]uint32),
		shared:  make(map[SharedPolicyKey]PolicyEntry),
	}

	var errs error
	err := f.overlayMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*OverlayKey)
		val, okV := v.(*OverlayValue)
		if !okK || !okV {
			errs = errors.Join(errs, fmt.Errorf("unexpected policy overlay map entry %T: %T", k, v))
			return
		}
		s.overlay[uint16(key.EndpointID)] = val.RuleSetID
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump policy overlay map: %w", err)
	}
	if errs != nil {
		return nil, errs
	}

	err = f.sharedMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key, okK := k.(*SharedPolicyKey)
		val, okV := v.(*PolicyEntry)
		if !okK || !okV {
			errs = errors.Join(errs, fmt.Errorf("unexpected shared policy map entry %T: %T", k, v))
			return
		}
		s.shared[*key] = *val
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump shared policy map: %w", err)
	}
	if errs != nil {
		return nil, errs
	}
	return s, nil
}

// reconcileSharedPolicy makes the shared policy map and the policy overlay map match the rule
// sets and endpoints that the agent recorded, in case something else changed them, e.g. by
// hand or because of a kernel issue. This is the shared policy map's equivalent of the
// periodic reconciliation of per-endpoint policy maps. It returns the number of entries it
// fixed.
func (f *factory) reconcileSharedPolicy() (int, error) {
	if f.allocator == nil {
		return 0, nil
	}

	// Read the maps without the lock, so that policy updates are not blocked while the maps
	// are dumped. Each difference is checked again with the lock held before it is fixed, so
	// that changes made by policy updates in the meantime are kept.
	s, err := f.snapshotSharedPolicy()
	if err != nil {
		return 0, err
	}

	a := f.allocator
	a.mu.Lock()
	defer a.mu.Unlock()
	return f.reconcileSharedPolicyLocked(s)
}

// reconcileSharedPolicyLocked fixes the differences between the snapshot of the maps and the
// recorded rule sets and endpoints:
//   - Entries of rule sets in use that are missing or differ are written.
//   - Entries that are not part of a rule set in use are deleted. This includes any entry of
//     lockdownRuleSetID, which must have none.
//   - Overlay entries of endpoints that use a rule set are written if they are missing or
//     point to another rule set.
//   - Overlay entries of other endpoints are deleted if they point to a rule set, as the
//     agent gave those endpoints none. Overlay entries that point to lockdownRuleSetID,
//     e.g. of endpoints in lockdown, are left alone.
//
// The rule set entries are fixed before the overlay entries, so that an endpoint never points
// to an incomplete rule set.
func (f *factory) reconcileSharedPolicyLocked(s *sharedPolicySnapshot) (int, error) {
	a := f.allocator
	f.deletePendingRuleSetsLocked()

	fixed := 0
	var errs error

	// The entries of rule sets in use. Unused rule sets whose entries could not be deleted
	// yet are left to deletePendingRuleSetsLocked.
	want := make(map[SharedPolicyKey]PolicyEntry)
	for id, entry := range a.byID {
		if _, pending := a.pendingDelete[id]; pending {
			continue
		}
		for _, r := range entry.rules {
			want[r.Key] = r.Entry
		}
	}

	for key, entry := range want {
		if got, ok := s.shared[key]; ok && got == entry {
			continue
		}
		// A lookup in an LPM trie returns the longest entry that matches the key: the entry
		// itself if it exists, else a shorter one. The agent's shorter entries never equal
		// entry, as the flags of an entry hold its prefix length.
		if v, err := f.sharedMap.Lookup(&key); err == nil {
			if got, ok := v.(*PolicyEntry); ok && *got == entry {
				continue
			}
		}
		if err := f.sharedMap.Update(&key, &entry); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to write shared policy map entry %s: %w", key.String(), err))
			continue
		}
		fixed++
	}

	for key := range s.shared {
		if _, ok := want[key]; ok {
			continue
		}
		if _, pending := a.pendingDelete[key.RuleSetID]; pending {
			continue
		}
		// Deleting from an LPM trie needs an exact match. An entry that is already gone
		// was deleted by a policy update since the snapshot.
		if err := f.sharedMap.Delete(&key); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = errors.Join(errs, fmt.Errorf("failed to delete shared policy map entry %s: %w", key.String(), err))
			}
			continue
		}
		fixed++
	}

	for epID, id := range a.epToRuleSetID {
		if got, ok := s.overlay[epID]; ok && got == id {
			continue
		}
		if v, err := f.overlayMap.Lookup(&OverlayKey{EndpointID: uint32(epID)}); err == nil {
			if got, ok := v.(*OverlayValue); ok && got.RuleSetID == id {
				continue
			}
		}
		if err := f.updateOverlayPolicyEntryLocked(epID, id); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to write policy overlay entry of endpoint %d: %w", epID, err))
			continue
		}
		fixed++
	}

	for epID, id := range s.overlay {
		if _, ok := a.epToRuleSetID[epID]; ok || id == lockdownRuleSetID {
			continue
		}
		// The endpoint may have been locked down since the snapshot.
		key := OverlayKey{EndpointID: uint32(epID)}
		v, err := f.overlayMap.Lookup(&key)
		if err != nil {
			continue
		}
		if got, ok := v.(*OverlayValue); !ok || got.RuleSetID == lockdownRuleSetID {
			continue
		}
		if err := f.overlayMap.Delete(&key); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = errors.Join(errs, fmt.Errorf("failed to delete policy overlay entry of endpoint %d: %w", epID, err))
			}
			continue
		}
		fixed++
	}

	return fixed, errs
}

// reconcileSharedPolicyJob runs reconcileSharedPolicy periodically, see registerSharedPolicy.
func (f *factory) reconcileSharedPolicyJob(context.Context) error {
	fixed, err := f.reconcileSharedPolicy()
	if fixed > 0 {
		f.logger.Warn("Fixed shared policy map entries that differed from the agent's state",
			logfields.Count, fixed,
		)
	}
	return err
}
