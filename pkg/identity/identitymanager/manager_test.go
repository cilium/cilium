// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

var (
	idFooSelectLabels = labels.NewLabelsFromModel([]string{"id=foo"})
	idBarSelectLabels = labels.NewLabelsFromModel([]string{"id=bar"})
	fooIdentity       = identity.NewIdentity(identity.NumericIdentity(12345), idFooSelectLabels)
	fooIdentity2      = identity.NewIdentity(identity.NumericIdentity(12345), idFooSelectLabels)
	barIdentity       = identity.NewIdentity(identity.NumericIdentity(54321), idBarSelectLabels)
)

func TestIdentityManagerLifecycle(t *testing.T) {
	idm := NewIdentityManager()
	require.NotNil(t, idm.identities)

	_, exists := idm.identities[fooIdentity.ID]
	require.Equal(t, false, exists)

	idm.Add(fooIdentity)
	require.Equal(t, uint(1), idm.identities[fooIdentity.ID].refCount)

	idm.Add(fooIdentity)
	require.Equal(t, uint(2), idm.identities[fooIdentity.ID].refCount)

	idm.Add(barIdentity)
	require.Equal(t, uint(1), idm.identities[barIdentity.ID].refCount)

	idm.Remove(fooIdentity)
	require.Equal(t, uint(1), idm.identities[fooIdentity.ID].refCount)

	idm.Remove(fooIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	require.Equal(t, false, exists)

	_, exists = idm.identities[barIdentity.ID]
	require.True(t, exists)

	idm.Remove(barIdentity)
	_, exists = idm.identities[barIdentity.ID]
	require.Equal(t, false, exists)

	idm.Add(fooIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	require.True(t, exists)
	idm.RemoveOldAddNew(fooIdentity, barIdentity)
	_, exists = idm.identities[fooIdentity.ID]
	require.Equal(t, false, exists)
	_, exists = idm.identities[barIdentity.ID]
	require.True(t, exists)
	require.Equal(t, uint(1), idm.identities[barIdentity.ID].refCount)

	idm.RemoveOldAddNew(nil, barIdentity)
	require.Equal(t, uint(2), idm.identities[barIdentity.ID].refCount)
}

func TestHostIdentityLifecycle(t *testing.T) {
	idm := NewIdentityManager()
	require.NotNil(t, idm.identities)

	hostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, labels.LabelHost)
	_, exists := idm.identities[hostIdentity.ID]
	require.Equal(t, false, exists)

	idm.Add(hostIdentity)
	require.Equal(t, uint(1), idm.identities[hostIdentity.ID].refCount)

	newHostLabels := labels.NewLabelsFromModel([]string{"id=foo"})
	newHostLabels.MergeLabels(labels.LabelHost)
	newHostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, newHostLabels)
	idm.RemoveOldAddNew(hostIdentity, newHostIdentity)
	require.Equal(t, uint(1), idm.identities[hostIdentity.ID].refCount)
	require.EqualValues(t, newHostIdentity, idm.identities[hostIdentity.ID].identity)
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

func TestLocalEndpointIdentityAdded(t *testing.T) {
	idm := NewIdentityManager()
	observer := newIdentityManagerObserver([]identity.NumericIdentity{}, []identity.NumericIdentity{})
	idm.Subscribe(observer)

	// No-op: nil Identity.
	idm.Add(nil)
	expectedObserver := newIdentityManagerObserver([]identity.NumericIdentity{}, []identity.NumericIdentity{})
	require.EqualValues(t, expectedObserver, observer)

	// First add triggers an "IdentityAdded" event.
	idm.Add(fooIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID}, []identity.NumericIdentity{})
	require.EqualValues(t, expectedObserver, observer)

	// Second does not.
	idm.Add(fooIdentity)
	require.EqualValues(t, expectedObserver, observer)
	require.Equal(t, uint(2), idm.identities[fooIdentity.ID].refCount)

	// Duplicate identity with the same ID does not trigger events.
	idm.Add(fooIdentity2)
	require.EqualValues(t, expectedObserver, observer)
	require.Equal(t, uint(3), idm.identities[fooIdentity.ID].refCount)

	// Unrelated add should also trigger.
	idm.Add(barIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID}, []identity.NumericIdentity{})
	require.EqualValues(t, expectedObserver, observer)
	require.Equal(t, uint(1), idm.identities[barIdentity.ID].refCount)

	// Removing both then re-adding should trigger the event again.
	idm.Remove(fooIdentity)
	require.Equal(t, uint(2), idm.identities[fooIdentity.ID].refCount)
	idm.Remove(fooIdentity)
	require.Equal(t, uint(1), idm.identities[fooIdentity.ID].refCount)
	idm.Remove(fooIdentity)
	require.Equal(t, 2, len(observer.added))
	require.Equal(t, 1, len(observer.removed))
	idm.Add(fooIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID, fooIdentity.ID}, []identity.NumericIdentity{fooIdentity.ID})
	require.EqualValues(t, expectedObserver, observer)

	// RemoveOldAddNew with the same ID is a no-op
	idm.RemoveOldAddNew(fooIdentity, fooIdentity2)
	require.EqualValues(t, expectedObserver, observer)

	// RemoveOldAddNew from an existing ID to another triggers removal of the old
	idm.RemoveOldAddNew(barIdentity, fooIdentity)
	expectedObserver = newIdentityManagerObserver([]identity.NumericIdentity{fooIdentity.ID, barIdentity.ID, fooIdentity.ID}, []identity.NumericIdentity{fooIdentity.ID, barIdentity.ID})
	require.EqualValues(t, expectedObserver, observer)
}

func TestLocalEndpointIdentityRemoved(t *testing.T) {
	idm := NewIdentityManager()
	require.NotNil(t, idm.identities)
	observer := newIdentityManagerObserver([]identity.NumericIdentity{}, []identity.NumericIdentity{})
	idm.Subscribe(observer)

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
	require.EqualValues(t, expectedObserver, observer)

	idm = NewIdentityManager()
	require.NotNil(t, idm.identities)
	observer = newIdentityManagerObserver(nil, []identity.NumericIdentity{})
	idm.Subscribe(observer)

	// Refcount remove
	idm.Add(fooIdentity)    // foo = 1
	idm.Add(fooIdentity)    // foo = 2
	idm.Add(barIdentity)    // bar = 1
	idm.Remove(fooIdentity) // foo = 1
	expectedObserver = newIdentityManagerObserver(nil, []identity.NumericIdentity{})
	require.EqualValues(t, expectedObserver, observer)
	idm.Remove(fooIdentity) // foo = 0
	expectedObserver = newIdentityManagerObserver(nil, []identity.NumericIdentity{fooIdentity.ID})
	require.EqualValues(t, expectedObserver, observer)
	idm.Remove(barIdentity) // bar = 0
	expectedObserver = newIdentityManagerObserver(nil, []identity.NumericIdentity{fooIdentity.ID, barIdentity.ID})
	require.EqualValues(t, expectedObserver, observer)
}
