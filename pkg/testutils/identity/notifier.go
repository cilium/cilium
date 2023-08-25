// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testidentity

import (
	"net"

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
//
// It doesn't implement the identity allocation semantics of the interface.
func (d *DummyIdentityNotifier) RegisterForIdentityUpdatesLocked(selector api.FQDNSelector) {
	if _, ok := d.selectors[selector]; !ok {
		d.selectors[selector] = []identity.NumericIdentity{}
	}
}

// UnregisterForIdentityUpdatesLocked stops managing this selector.
func (d *DummyIdentityNotifier) UnregisterForIdentityUpdatesLocked(selector api.FQDNSelector) {
	delete(d.selectors, selector)
}

// MapSelectorsToIPsLocked is a dummy implementation that does not implement
// the selectors of the real implementation.
func (d *DummyIdentityNotifier) MapSelectorsToIPsLocked(fqdnSelectors map[api.FQDNSelector]struct{}) (selectorsMissingIPs []api.FQDNSelector, selectorIPMapping map[api.FQDNSelector][]net.IP) {
	return nil, nil
}
