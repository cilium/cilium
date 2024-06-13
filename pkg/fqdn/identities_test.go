// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fqdn

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type mockIdentityAllocator struct {
	allocations chan labels.Labels
	releases    chan labels.Labels
}

func newMockIdentityAllocator() *mockIdentityAllocator {
	return &mockIdentityAllocator{
		allocations: make(chan labels.Labels),
		releases:    make(chan labels.Labels),
	}
}

func (m *mockIdentityAllocator) AllocateLocalIdentity(lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error) {
	m.allocations <- lbls
	return &identity.Identity{ID: oldNID, Labels: lbls}, false, nil
}

func (m *mockIdentityAllocator) Release(ctx context.Context, id *identity.Identity, notifyOwner bool) (released bool, err error) {
	m.releases <- id.Labels
	return false, nil
}

func TestNameManagerIdentityPreAllocation(t *testing.T) {
	ipc := newMockIPCache()
	ida := newMockIdentityAllocator()
	nameManager := NewNameManager(Config{
		MinTTL:            1,
		Cache:             NewDNSCache(0),
		IPCache:           ipc,
		IdentityAllocator: ida,
	})
	t.Cleanup(nameManager.identityQueue.trigger.Shutdown)

	// Register three selectors in sequence. This also tests that allocation
	// happens asynchronously as our the mock identity allocator blocks
	// until we read its channel
	nameManager.RegisterFQDNSelector(ciliumIOSel)
	nameManager.RegisterFQDNSelector(ciliumIOSelMatchPattern)
	nameManager.RegisterFQDNSelector(githubSel)
	for _, lbls := range identitiesForFQDNSelector(ciliumIOSel) {
		require.Equal(t, lbls, <-ida.allocations)
	}
	for _, lbls := range identitiesForFQDNSelector(ciliumIOSelMatchPattern) {
		require.Equal(t, lbls, <-ida.allocations)
	}
	for _, lbls := range identitiesForFQDNSelector(githubSel) {
		require.Equal(t, lbls, <-ida.allocations)
	}

	// Bad cases: Unregister a selector which does not exist, and register a
	// selector twice.
	// Note: We check that these did not cause any allocation releases below,
	// after the "Unregistering in sequence" block - as we're certain that the
	// trigger has run after we've observed all legitimate releases
	nameManager.RegisterFQDNSelector(ciliumIOSel)
	nameManager.UnregisterFQDNSelector(api.FQDNSelector{
		MatchName: "does.not.exist",
	})

	// Unregistering in sequence
	nameManager.UnregisterFQDNSelector(ciliumIOSel)
	nameManager.UnregisterFQDNSelector(githubSel)
	nameManager.UnregisterFQDNSelector(ciliumIOSelMatchPattern)
	for _, lbls := range identitiesForFQDNSelector(ciliumIOSel) {
		require.Equal(t, lbls, <-ida.releases)
	}
	for _, lbls := range identitiesForFQDNSelector(githubSel) {
		require.Equal(t, lbls, <-ida.releases)
	}
	for _, lbls := range identitiesForFQDNSelector(ciliumIOSelMatchPattern) {
		require.Equal(t, lbls, <-ida.releases)
	}

	// Check that the "bad cases" did not trigger any actions
	require.Empty(t, ida.allocations)
	require.Empty(t, ida.releases)
}
