// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"log/slog"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type NoopIdentityAllocator struct {
	logger *slog.Logger
	// allocatorInitialized is closed when the allocator is initialized.
	allocatorInitialized chan struct{}
}

func NewNoopIdentityAllocator(logger *slog.Logger) *NoopIdentityAllocator {
	return &NoopIdentityAllocator{
		logger:               logger,
		allocatorInitialized: make(chan struct{}),
	}
}

func (n *NoopIdentityAllocator) WaitForInitialGlobalIdentities(context.Context) error {
	return nil
}

func (n *NoopIdentityAllocator) AllocateIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (*identity.Identity, bool, error) {
	n.logger.Debug(
		"Assigning a fixed identity that is not based on labels, because network policies are disabled",
		logfields.Identity, identity.ReservedIdentityInit,
		logfields.IdentityLabels, lbls,
	)

	initID := identity.LookupReservedIdentity(identity.ReservedIdentityInit)
	return initID, false, nil
}

func (n *NoopIdentityAllocator) Release(context.Context, *identity.Identity, bool) (released bool, err error) {
	// No need to release identities. All endpoints will have the same identity.
	// The existing global identities will be cleaned up.
	return false, nil
}

func (n *NoopIdentityAllocator) LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity {
	// Lookup only reserved identities.
	return identity.LookupReservedIdentityByLabels(lbls)
}

func (n *NoopIdentityAllocator) LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity {
	// Lookup only reserved identities.
	return identity.LookupReservedIdentity(id)
}

func (n *NoopIdentityAllocator) GetIdentityCache() identity.IdentityMap {
	// Return only reserved identities, because reserved identities are
	// statically initialized and are not managed by identity allocator.
	cache := identity.IdentityMap{}

	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		cache[ni] = id.Labels.LabelArray()
	})

	return cache
}

func (n *NoopIdentityAllocator) GetIdentities() IdentitiesModel {
	// Return only reserved identities, because reserved identities are
	// statically initialized and are not managed by identity allocator.
	identities := IdentitiesModel{}

	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		identities = append(identities, identitymodel.CreateModel(id))
	})

	return identities
}

func (n *NoopIdentityAllocator) WithholdLocalIdentities(nids []identity.NumericIdentity) {
	// No-op, because local identities are not used when network policies are disabled.
}

func (n *NoopIdentityAllocator) UnwithholdLocalIdentities(nids []identity.NumericIdentity) {
	// No-op, because local identities are not used when network policies are disabled.
}

type NoopRemoteIDCache struct{}

func (n *NoopRemoteIDCache) NumEntries() int {
	return 0
}

func (n *NoopRemoteIDCache) Synced() bool {
	return true
}

func (n *NoopRemoteIDCache) Watch(ctx context.Context, onSync func(context.Context)) {
	onSync(ctx)
}

func (n *NoopIdentityAllocator) WatchRemoteIdentities(remoteName string, remoteID uint32, backend kvstore.BackendOperations, cachedPrefix bool) (allocator.RemoteIDCache, error) {
	// Remote watchers are not used when the cluster has network policies disabled.
	return &NoopRemoteIDCache{}, nil
}

func (n *NoopIdentityAllocator) RemoveRemoteIdentities(name string) {
	// No-op, because remote identities are not used when network policies are disabled.
}

func (n *NoopIdentityAllocator) InitIdentityAllocator(versioned.Interface) <-chan struct{} {
	close(n.allocatorInitialized)
	return n.allocatorInitialized
}

func (n *NoopIdentityAllocator) RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error) {
	// No-op, because local identities are not used when network policies are disabled.
	return make(map[identity.NumericIdentity]*identity.Identity), nil
}

func (n *NoopIdentityAllocator) ReleaseRestoredIdentities() {
	// No-op, because restored identities are not used when network policies are disabled.
}

func (n *NoopIdentityAllocator) Close() {}

func (m *NoopIdentityAllocator) Observe(ctx context.Context, next func(IdentityChange), complete func(error)) {
	// No-op, because identities are not managed.
	complete(nil)
}

// Noop identity allocator is itself a noop observable, just return itself as the local identity observable.
func (m *NoopIdentityAllocator) LocalIdentityChanges() stream.Observable[IdentityChange] {
	return m
}
