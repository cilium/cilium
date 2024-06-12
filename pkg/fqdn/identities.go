// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"errors"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	identityAllocationTriggerName     = "fqdn-selector-identity-pre-allocation"
	identityAllocationTriggerInterval = 100 * time.Millisecond
)

// newIdentityAllocationQueue creates a new queue to asynchronously allocate
// and release identities for FQDNSelectors. This is done asynchronously to
// avoid deadlocks:
// We must not hold the NameManager lock when calling AllocateLocalIdentity
// with notifyOwner=true, as the owner is the SelectorCache which can call
// into NameManager (via RegisterFQDNSelector or UnregisterFQDNSelector),
// thus creating a cyclic lock dependency which would lead to deadlocks.
func newIdentityAllocationQueue(allocator IdentityAllocator) *identityQueue {
	a := newIdentityPreAllocator(allocator)
	ctx, cancel := context.WithCancel(context.Background())

	q := &identityQueue{}
	q.trigger, _ = trigger.NewTrigger(trigger.Parameters{
		Name:        identityAllocationTriggerName,
		MinInterval: identityAllocationTriggerInterval,
		TriggerFunc: func(reasons []string) {
			for _, item := range q.drain() {
				if item.allocate {
					if err := a.allocate(item.selector); err != nil {
						log.WithError(err).WithField(logfields.Selector, item.selector).
							Error("Failed to pre-allocate identity")
					}
				} else {
					if err := a.release(ctx, item.selector); err != nil {
						log.WithError(err).WithField(logfields.Selector, item.selector).
							Error("Failed to release pre-allocated identity")
					}
				}
			}
		},
		ShutdownFunc: cancel,
	})

	return q
}

// identityPreAllocator wraps the real IdentityAllocator and stores
// the pre-allocated identities for easier release
type identityPreAllocator struct {
	preAllocatedIdentities map[api.FQDNSelector][]*identity.Identity
	backend                IdentityAllocator
}

func newIdentityPreAllocator(allocator IdentityAllocator) *identityPreAllocator {
	return &identityPreAllocator{
		preAllocatedIdentities: make(map[api.FQDNSelector][]*identity.Identity),
		backend:                allocator,
	}
}

// identitiesForFQDNSelector returns a slice of identity labels we want to
// pre-allocate for this selector. If we are running in dual-stack mode, we
// want to allocate one identity for IPv4 and IPv6 each, otherwise we only
// need to allocate a single identity
func identitiesForFQDNSelector(selector api.FQDNSelector) []labels.Labels {
	selectorLbl := selector.IdentityLabel()
	if option.Config.IsDualStack() {
		return []labels.Labels{
			labels.FromSlice([]labels.Label{selectorLbl, labels.WorldLabelV4}),
			labels.FromSlice([]labels.Label{selectorLbl, labels.WorldLabelV6}),
		}
	} else {
		return []labels.Labels{
			labels.FromSlice([]labels.Label{selectorLbl, labels.WorldLabelNonDualStack}),
		}
	}
}

func (a *identityPreAllocator) allocate(selector api.FQDNSelector) (err error) {
	_, ok := a.preAllocatedIdentities[selector]
	if ok {
		return errors.New("attempted to pre-allocate already pre-allocated identity")
	}

	requiredIdentities := identitiesForFQDNSelector(selector)
	allocatedIdentities := make([]*identity.Identity, 0, len(requiredIdentities))
	for _, lbls := range requiredIdentities {
		id, _, allocErr := a.backend.AllocateLocalIdentity(lbls, true, identity.IdentityUnknown)
		if allocErr != nil {
			// This should never happen, unless we ran out of local identities.
			// Since this is pre-allocation only (which is an optimization
			// and not needed for correctness), we don't retry here.
			// There is still a chance that the system recovers by itself
			// if identities are released as part of the IPCache label
			// injection triggered by updateMetadata.
			err = errors.Join(err, allocErr)
			// In case the previous allocation succeeded, we still want to
			// add it to preAllocatedIdentities in order to release it later
			continue
		}
		allocatedIdentities = append(allocatedIdentities, id)
	}

	if len(allocatedIdentities) > 0 {
		a.preAllocatedIdentities[selector] = allocatedIdentities
	}
	return err
}

func (a *identityPreAllocator) release(ctx context.Context, selector api.FQDNSelector) (err error) {
	identities, ok := a.preAllocatedIdentities[selector]
	if !ok {
		return errors.New("attempted to release non-allocated identity")
	}

	// Always delete the bookkeeping for pre-allocated identity even if release
	// fails, as release basically only fails if we have a bug in our code.
	// No point in re-trying in such a case.
	delete(a.preAllocatedIdentities, selector)

	for _, id := range identities {
		_, releaseErr := a.backend.Release(ctx, id, true)
		if releaseErr != nil {
			err = errors.Join(err, releaseErr)
		}
	}

	return nil
}

type identityQueueItem struct {
	selector api.FQDNSelector
	allocate bool // true -> allocate, false -> release
}

type identityQueue struct {
	lock    lock.Mutex
	queue   []identityQueueItem
	trigger *trigger.Trigger
}

func (q *identityQueue) drain() (items []identityQueueItem) {
	q.lock.Lock()
	defer q.lock.Unlock()

	items, q.queue = q.queue, []identityQueueItem{}
	return items
}

func (q *identityQueue) enqueueItem(item identityQueueItem) {
	q.lock.Lock()
	defer q.lock.Unlock()

	// Note that we enqueue items in sequence, thereby preserving the order of
	// allocate and release events emitted by the NameManager. This ensures we
	// are not releasing identities before they are allocated.
	q.queue = append(q.queue, item)
	q.trigger.Trigger()
}

func (q *identityQueue) enqueueAllocation(selector api.FQDNSelector) {
	q.enqueueItem(identityQueueItem{
		selector: selector,
		allocate: true,
	})
}

func (q *identityQueue) enqueueRelease(selector api.FQDNSelector) {
	q.enqueueItem(identityQueueItem{
		selector: selector,
		allocate: false,
	})
}
