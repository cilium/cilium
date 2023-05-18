// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IdentityManagerTestSuite struct{}

var (
	_ = Suite(&IdentityManagerTestSuite{})

	idFooSelectLabels = labels.NewLabelsFromModel([]string{"id=foo"})
	idBarSelectLabels = labels.NewLabelsFromModel([]string{"id=bar"})
	fooIdentity       = identity.NewIdentity(identity.NumericIdentity(12345), idFooSelectLabels)
	fooIdentity2      = identity.NewIdentity(identity.NumericIdentity(12345), idFooSelectLabels)
	barIdentity       = identity.NewIdentity(identity.NumericIdentity(54321), idBarSelectLabels)
)

func (s *IdentityManagerTestSuite) TestIdentityManagerLifecycle(c *C) {
	idm := NewIdentityManager()
	c.Assert(idm.identities, Not(IsNil))

	_, exists := idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, false)

	idm.Add(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(1))

	idm.Add(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(2))

	idm.Add(barIdentity)
	c.Assert(idm.identities[barIdentity.ID].refCount, Equals, uint(1))

	idm.Remove(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(1))

	idm.Remove(fooIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, false)

	_, exists = idm.identities[barIdentity.ID]
	c.Assert(exists, Equals, true)

	idm.Remove(barIdentity)
	_, exists = idm.identities[barIdentity.ID]
	c.Assert(exists, Equals, false)

	idm.Add(fooIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, true)
	idm.RemoveOldAddNew(fooIdentity, barIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	c.Assert(exists, Equals, false)
	_, exists = idm.identities[barIdentity.ID]
	c.Assert(exists, Equals, true)
	c.Assert(idm.identities[barIdentity.ID].refCount, Equals, uint(1))

	idm.RemoveOldAddNew(nil, barIdentity)
	c.Assert(idm.identities[barIdentity.ID].refCount, Equals, uint(2))
}

func (s *IdentityManagerTestSuite) TestHostIdentityLifecycle(c *C) {
	idm := NewIdentityManager()
	c.Assert(idm.identities, Not(IsNil))

	hostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, labels.LabelHost)
	_, exists := idm.identities[hostIdentity.ID]
	c.Assert(exists, Equals, false)

	idm.Add(hostIdentity)
	c.Assert(idm.identities[hostIdentity.ID].refCount, Equals, uint(1))

	newHostLabels := labels.NewLabelsFromModel([]string{"id=foo"})
	newHostLabels.MergeLabels(labels.LabelHost)
	newHostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, newHostLabels)
	idm.RemoveOldAddNew(hostIdentity, newHostIdentity)
	c.Assert(idm.identities[hostIdentity.ID].refCount, Equals, uint(1))
	c.Assert(idm.identities[hostIdentity.ID].identity, checker.DeepEquals, newHostIdentity)
}

type identityManagerObserver struct {
	added   []identity.NumericIdentity
	removed []identity.NumericIdentity
}

func newIdentityManagerObserver(trackAdd, trackRemove []identity.NumericIdentity) *identityManagerObserver {
	return &identityManagerObserver{
		added:   trackAdd,
		removed: trackRemove,
	}
}

func (i *identityManagerObserver) LocalEndpointIdentityAdded(identity *identity.Identity) {
	if i.added != nil {
		i.added = append(i.added, identity.ID)
	}
}

func (i *identityManagerObserver) LocalEndpointIdentityRemoved(identity *identity.Identity) {
	if i.removed != nil {
		i.removed = append(i.removed, identity.ID)
	}
}

func (s *IdentityManagerTestSuite) TestLocalEndpointIdentityAdded(c *C) {
	idm := NewIdentityManager()
	observer := newIdentityManagerObserver([]identity.NumericIdentity{}, []identity.NumericIdentity{})
	idm.subscribe(observer)

	// No-op: nil Identity.
	idm.Add(nil)
	expectedObserver := newIdentityManagerObserver([]identity.NumericIdentity{}, []identity.NumericIdentity{})
	c.Assert(observer, checker.DeepEquals, expectedObserver)

	// First add triggers an "IdentityAdded" event.
	idm.Add(fooIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID}, []identity.NumericIdentity{})
	c.Assert(observer, checker.DeepEquals, expectedObserver)

	// Second does not.
	idm.Add(fooIdentity)
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(2))

	// Duplicate identity with the same ID does not trigger events.
	idm.Add(fooIdentity2)
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(3))

	// Unrelated add should also trigger.
	idm.Add(barIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID}, []identity.NumericIdentity{})
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	c.Assert(idm.identities[barIdentity.ID].refCount, Equals, uint(1))

	// Removing both then re-adding should trigger the event again.
	idm.Remove(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(2))
	idm.Remove(fooIdentity)
	c.Assert(idm.identities[fooIdentity.ID].refCount, Equals, uint(1))
	idm.Remove(fooIdentity)
	c.Assert(observer.added, HasLen, 2)
	c.Assert(observer.removed, HasLen, 1)
	idm.Add(fooIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID, fooIdentity.ID}, []identity.NumericIdentity{fooIdentity.ID})
	c.Assert(observer, checker.DeepEquals, expectedObserver)

	// RemoveOldAddNew with the same ID is a no-op
	idm.RemoveOldAddNew(fooIdentity, fooIdentity2)
	c.Assert(observer, checker.DeepEquals, expectedObserver)

	// RemoveOldAddNew from an existing ID to another triggers removal of the old
	idm.RemoveOldAddNew(barIdentity, fooIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID, fooIdentity.ID}, []identity.NumericIdentity{fooIdentity.ID, barIdentity.ID})
	c.Assert(observer, checker.DeepEquals, expectedObserver)
}

func (s *IdentityManagerTestSuite) TestLocalEndpointIdentityRemoved(c *C) {
	idm := NewIdentityManager()
	c.Assert(idm.identities, NotNil)
	observer := newIdentityManagerObserver([]identity.NumericIdentity{}, []identity.NumericIdentity{})
	idm.subscribe(observer)

	// No-ops:
	// - nil Identity.
	// - Identity that isn't managed
	idm.Remove(nil)
	// This will log a warnign!
	idm.Remove(fooIdentity)

	// Basic remove
	idm.Add(fooIdentity)
	idm.Remove(fooIdentity)
	expectedObserver := newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID}, []identity.NumericIdentity{fooIdentity.ID})
	c.Assert(observer, checker.DeepEquals, expectedObserver)

	idm = NewIdentityManager()
	c.Assert(idm.identities, NotNil)
	observer = newIdentityManagerObserver(nil, []identity.NumericIdentity{})
	idm.subscribe(observer)

	// Refcount remove
	idm.Add(fooIdentity)    // foo = 1
	idm.Add(fooIdentity)    // foo = 2
	idm.Add(barIdentity)    // bar = 1
	idm.Remove(fooIdentity) // foo = 1
	expectedObserver = newIdentityManagerObserver(nil, []identity.NumericIdentity{})
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	idm.Remove(fooIdentity) // foo = 0
	expectedObserver = newIdentityManagerObserver(nil, []identity.NumericIdentity{fooIdentity.ID})
	c.Assert(observer, checker.DeepEquals, expectedObserver)
	idm.Remove(barIdentity) // bar = 0
	expectedObserver = newIdentityManagerObserver(nil, []identity.NumericIdentity{fooIdentity.ID, barIdentity.ID})
	c.Assert(observer, checker.DeepEquals, expectedObserver)
}
