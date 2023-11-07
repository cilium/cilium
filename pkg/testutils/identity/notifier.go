// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testidentity

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
)

type DummyIdentityNotifier struct {
	mutex     lock.Mutex
	selectors map[api.FQDNSelector][]netip.Addr
}

func NewDummyIdentityNotifier() *DummyIdentityNotifier {
	return &DummyIdentityNotifier{
		selectors: make(map[api.FQDNSelector][]netip.Addr),
	}
}

// Lock must be held during any calls to RegisterForIPUpdatesLocked or
// UnregisterForIPUpdatesLocked.
func (d *DummyIdentityNotifier) Lock() {
	d.mutex.Lock()
}

// Unlock must be called after calls to RegisterForIPUpdatesLocked or
// UnregisterForIPUpdatesLocked are done.
func (d *DummyIdentityNotifier) Unlock() {
	d.mutex.Unlock()
}

// RegisterForIPUpdatesLocked starts managing this selector.
//
// It doesn't implement the identity allocation semantics of the interface.
func (d *DummyIdentityNotifier) RegisterForIPUpdatesLocked(selector api.FQDNSelector) []netip.Addr {
	return d.selectors[selector]
}

// UnregisterForIPUpdatesLocked stops managing this selector.
func (d *DummyIdentityNotifier) UnregisterForIPUpdatesLocked(selector api.FQDNSelector) {
	delete(d.selectors, selector)
}

func (d *DummyIdentityNotifier) SetSelectorIPs(selector api.FQDNSelector, ips []netip.Addr) {
	d.selectors[selector] = ips
}
