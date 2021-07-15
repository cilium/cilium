// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package testutils

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
)

type DummyIdentityNotifier struct {
	mutex     lock.Mutex
	selectors map[api.FQDNSelector][]identity.NumericIdentity
}

func NewDummyIdentityNotifier() *DummyIdentityNotifier {
	return &DummyIdentityNotifier{
		selectors: make(map[api.FQDNSelector][]identity.NumericIdentity),
	}
}

// Lock must be held during any calls to RegisterForIdentityUpdatesLocked or
// UnregisterForIdentityUpdatesLocked.
func (d *DummyIdentityNotifier) Lock() {
	d.mutex.Lock()
}

// Unlock must be called after calls to RegisterForIdentityUpdatesLocked or
// UnregisterForIdentityUpdatesLocked are done.
func (d *DummyIdentityNotifier) Unlock() {
	d.mutex.Unlock()
}

// RegisterForIdentityUpdatesLocked starts managing this selector.
func (d *DummyIdentityNotifier) RegisterForIdentityUpdatesLocked(selector api.FQDNSelector) (identities []identity.NumericIdentity) {
	ids, ok := d.selectors[selector]
	if !ok {
		d.selectors[selector] = []identity.NumericIdentity{}
	}
	return ids
}

// UnregisterForIdentityUpdatesLocked stops managing this selector.
func (d *DummyIdentityNotifier) UnregisterForIdentityUpdatesLocked(selector api.FQDNSelector) {
	delete(d.selectors, selector)
}

func (d *DummyIdentityNotifier) InjectIdentitiesForSelector(fqdnSel api.FQDNSelector, ids []identity.NumericIdentity) {
	d.selectors[fqdnSel] = ids
}

// IsRegistered returns whether this selector is being managed.
func (d *DummyIdentityNotifier) IsRegistered(selector api.FQDNSelector) bool {
	_, ok := d.selectors[selector]
	return ok
}
