// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
