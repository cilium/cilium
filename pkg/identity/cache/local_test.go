// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestBumpNextNumericIdentity(t *testing.T) {
	testutils.IntegrationTest(t)
	logger := hivetest.Logger(t)

	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	scope := identity.NumericIdentity(0x42_00_00_00)
	cache := newLocalIdentityCache(logger, scope, minID, maxID)

	for i := minID; i <= maxID; i++ {
		require.Equal(t, i, cache.nextNumericIdentity)
		cache.bumpNextNumericIdentity()
	}

	// ID must have overflowed and must be back to minID
	require.Equal(t, minID, cache.nextNumericIdentity)
}

func TestLocalIdentityCache(t *testing.T) {
	testutils.IntegrationTest(t)
	logger := hivetest.Logger(t)

	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(5)
	scope := identity.NumericIdentity(0x42_00_00_00)
	cache := newLocalIdentityCache(logger, scope, minID, maxID)

	identities := map[identity.NumericIdentity]*identity.Identity{}

	// allocate identities for all available numeric identities with a
	// unique label
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		require.NoError(t, err)
		require.True(t, isNew)
		require.Equal(t, scope+i, id.ID)
		identities[id.ID] = id
	}

	// allocate the same labels again. This must be successful and the same
	// identities must be returned.
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		require.False(t, isNew)
		require.NoError(t, err)

		// The returned identity must be identical
		require.Equal(t, identities[id.ID], id)
	}

	// Allocation must fail as we are out of IDs
	_, _, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity)
	require.Error(t, err)

	// release all identities, this must decrement the reference count but not release the identities yet
	for _, id := range identities {
		require.False(t, cache.release(id))
	}

	// lookup must still be successful
	for i := minID; i <= maxID; i++ {
		require.NotNil(t, cache.lookup(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)})))
		require.NotNil(t, cache.lookupByID(i|scope))
	}

	// release the identities a second time, this must cause the identity
	// to be forgotten
	for _, id := range identities {
		require.True(t, cache.release(id))
	}

	// allocate all identities again
	for i := minID; i <= maxID; i++ {
		id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{fmt.Sprintf("%d", i)}), identity.InvalidIdentity)
		require.NoError(t, err)
		require.True(t, isNew)
		identities[id.ID] = id
	}

	// release a random identity in the middle
	randomID := identity.NumericIdentity(3) | scope
	require.True(t, cache.release(identities[randomID]))

	id, isNew, err := cache.lookupOrCreate(labels.NewLabelsFromModel([]string{"foo"}), identity.InvalidIdentity)
	require.NoError(t, err)
	require.True(t, isNew)
	// the selected numeric identity must be the one released before
	require.Equal(t, randomID, id.ID)
}

func TestOldNID(t *testing.T) {
	logger := hivetest.Logger(t)
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(10)
	scope := identity.NumericIdentity(0x42_00_00_00)
	c := newLocalIdentityCache(logger, scope, minID, maxID)

	// Request identity, it should work
	l := labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32"))
	id, _, _ := c.lookupOrCreate(l, scope)
	assert.NotNil(t, id)
	assert.Equal(t, scope, id.ID)

	// Re-request identity, it should not
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.2/32"))
	id, _, _ = c.lookupOrCreate(l, scope)
	assert.NotNil(t, id)
	assert.Equal(t, scope+1, id.ID)

	// Withhold the next identity, it should be skipped
	c.withhold([]identity.NumericIdentity{scope + 2})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.3/32"))
	id, _, _ = c.lookupOrCreate(l, 0)
	assert.NotNil(t, id)
	assert.Equal(t, scope+3, id.ID)

	// Request a withheld identity, it should succeed
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.4/32"))
	id2, _, _ := c.lookupOrCreate(l, scope+2)
	assert.NotNil(t, id2)
	assert.Equal(t, scope+2, id2.ID)

	// Request a withheld and allocated identity, it should be ignored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.5/32"))
	id, _, _ = c.lookupOrCreate(l, scope+2)
	assert.NotNil(t, id)
	assert.Equal(t, scope+4, id.ID)

	// Unwithhold and release an identity, requesting should now succeed
	c.unwithhold([]identity.NumericIdentity{scope + 2})
	c.release(id2)
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.6/32"))
	id, _, _ = c.lookupOrCreate(l, scope+2)
	assert.NotNil(t, id)
	assert.Equal(t, scope+2, id.ID)

	// Request an identity out of scope, it should not be honored
	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.7/32"))
	id, _, _ = c.lookupOrCreate(l, scope-2)
	assert.NotNil(t, id)
	assert.Equal(t, scope+5, id.ID)

	// Withhold all identities; allocator should fall back to a (random) withheld identity
	c.withhold([]identity.NumericIdentity{scope + 6, scope + 7, scope + 8, scope + 9, scope + 10})

	l = labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.8/32"))
	id, _, _ = c.lookupOrCreate(l, scope-2)
	assert.NotNil(t, id)
	// actual value is random, just need it to succeed
	assert.True(t, id.ID >= scope+6 && id.ID <= scope+10, "%d <= %d <= %d", scope+6, id.ID, scope+10)
}

func TestObserve(t *testing.T) {
	logger := hivetest.Logger(t)
	minID, maxID := identity.NumericIdentity(1), identity.NumericIdentity(10)
	scope := identity.NumericIdentity(0x42_00_00_00)
	c := newLocalIdentityCache(logger, scope, minID, maxID)

	tctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(cancel)

	// Notification channels for two observers.
	ev := make(chan IdentityChange, 1)
	synced := make(chan struct{})
	ev2 := make(chan IdentityChange, 1)
	synced2 := make(chan struct{})

	c.Observe(tctx, func(ic IdentityChange) {
		switch ic.Kind {
		case IdentityChangeUpsert, IdentityChangeDelete:
			ev <- ic
		case IdentityChangeSync:
			close(synced)
		}
	}, func(err error) {
		// We don't actually expect this to complete, but let's be "future-proof"
		if !errors.Is(err, context.Canceled) {
			t.Errorf("completed with error: %v", err)
		}
	})
	<-synced

	// Allocate a CIDR identity.
	l := labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32"))
	id, _, _ := c.lookupOrCreate(l, scope)
	assert.NotNil(t, id)
	assert.Equal(t, scope, id.ID)

	e := <-ev
	assert.Empty(t, ev)
	assert.Equal(t, IdentityChangeUpsert, e.Kind)

	// No event when just increasing the refcount.
	_, created, _ := c.lookupOrCreate(l, scope)
	assert.False(t, created)
	assert.Empty(t, ev)
	// Decrease reference count again.
	assert.False(t, c.release(id))

	// Second observer.
	c.Observe(tctx, func(ic IdentityChange) {
		switch ic.Kind {
		case IdentityChangeUpsert, IdentityChangeDelete:
			ev2 <- ic
		case IdentityChangeSync:
			close(synced2)
		}
	}, func(err error) {
		if !errors.Is(err, context.Canceled) {
			t.Errorf("observer 2 completed with error: %v", err)
		}
		// We don't actually expect this to complete, but let's be "future-proof"
	})

	// Should replay state:
	e = <-ev2
	assert.Empty(t, ev2)
	assert.Equal(t, IdentityChangeUpsert, e.Kind)
	assert.Equal(t, id.ID, e.ID)
	<-synced2

	// Release allocated identity, should be observed by both.
	assert.True(t, c.release(id))
	e = <-ev
	assert.Empty(t, ev)
	assert.Equal(t, IdentityChangeDelete, e.Kind)
	e = <-ev2
	assert.Empty(t, ev2)
	assert.Equal(t, IdentityChangeDelete, e.Kind)

	// No event for releasing when there's nothing to release.
	assert.False(t, c.release(id))
	assert.Empty(t, ev)
	assert.Empty(t, ev2)
}
