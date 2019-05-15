// Copyright 2018 Authors of Cilium
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

package cache

import (
	"context"
	"fmt"
	"path"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// globalIdentity is the structure used to store an identity in the kvstore
type globalIdentity struct {
	labels.LabelArray
}

// GetKey() encodes a globalIdentity as string to be used as key-value store key.
// LabelArray is already sorted, so the key will be generated in sorted order.
func (gi globalIdentity) GetKey() string {
	str := ""
	for _, l := range gi.LabelArray {
		str += l.FormatForKVStore()
	}
	return kvstore.Encode([]byte(str))
}

// PutKey() decodes a globalIdentity from its string representation
func (gi globalIdentity) PutKey(v string) (allocator.AllocatorKey, error) {
	b, err := kvstore.Decode(v)
	if err != nil {
		return nil, err
	}
	return globalIdentity{labels.NewLabelArrayFromSortedList(string(b))}, nil
}

var (
	// IdentityAllocator is an allocator for security identities from the
	// kvstore.
	IdentityAllocator *allocator.Allocator
	// identityAllocatorInitialized is closed whenever the identity allocator is
	// initialized
	identityAllocatorInitialized = make(chan struct{})

	localIdentities *localIdentityCache

	// IdentitiesPath is the path to where identities are stored in the key-value
	// store.
	IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")

	// setupMutex synchronizes InitIdentityAllocator() and Close()
	setupMutex lock.Mutex

	watcher identityWatcher
)

// IdentityAllocatorOwner is the interface the owner of an identity allocator
// must implement
type IdentityAllocatorOwner interface {
	// UpdateIdentities will be called when identities have changed
	UpdateIdentities(added, deleted IdentityCache)

	// GetSuffix must return the node specific suffix to use
	GetNodeSuffix() string
}

// InitIdentityAllocator creates the the identity allocator. Only the
// first invocation of this function will have an effect.  Caller must
// have initialized well known identities before calling this (by
// calling identity.InitWellKnownIdentities()).
func InitIdentityAllocator(owner IdentityAllocatorOwner) {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	if IdentityAllocator != nil {
		log.Panic("InitIdentityAllocator() in succession without calling Close()")
	}

	log.Info("Initializing identity allocator")

	minID := idpool.ID(identity.MinimalAllocationIdentity)
	maxID := idpool.ID(identity.MaximumAllocationIdentity)
	events := make(allocator.AllocatorEventChan, 1024)

	// It is important to start listening for events before calling
	// NewAllocator() as it will emit events while filling the
	// initial cache
	watcher.watch(owner, events)

	a, err := allocator.NewAllocator(IdentitiesPath, globalIdentity{},
		allocator.WithMax(maxID), allocator.WithMin(minID),
		allocator.WithSuffix(owner.GetNodeSuffix()),
		allocator.WithEvents(events),
		allocator.WithMasterKeyProtection(),
		allocator.WithPrefixMask(idpool.ID(option.Config.ClusterID<<identity.ClusterIDShift)))
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize identity allocator")
	}

	IdentityAllocator = a
	close(identityAllocatorInitialized)
	localIdentities = newLocalIdentityCache(1, 0xFFFFFF, events)

}

// Close closes the identity allocator and allows to call
// InitIdentityAllocator() again
func Close() {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	select {
	case <-identityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if IdentityAllocator == nil {
			log.Panic("Close() called without calling InitIdentityAllocator() first")
		}
	}

	IdentityAllocator.Delete()
	watcher.stop()
	IdentityAllocator = nil
	identityAllocatorInitialized = make(chan struct{})
	localIdentities = nil
}

// WaitForInitialIdentities waits for the initial set of security identities to
// have been received and populated into the allocator cache
func WaitForInitialIdentities(ctx context.Context) error {
	select {
	case <-identityAllocatorInitialized:
	case <-ctx.Done():
		return fmt.Errorf("initial identity sync was cancelled: %s", ctx.Err())
	}

	return IdentityAllocator.WaitForInitialSync(ctx)
}

// IdentityAllocationIsLocal returns true if a call to AllocateIdentity with
// the given labels would not require accessing the KV store to allocate the
// identity.
// Currently, this function returns true only if the labels are those of a
// reserved identity, i.e. if the slice contains a single reserved
// "reserved:*" label.
func IdentityAllocationIsLocal(lbls labels.Labels) bool {
	// If there is only one label with the "reserved" source and a well-known
	// key, the well-known identity for it can be allocated locally.
	return LookupReservedIdentityByLabels(lbls) != nil
}

// AllocateIdentity allocates an identity described by the specified labels. If
// an identity for the specified set of labels already exist, the identity is
// re-used and reference counting is performed, otherwise a new identity is
// allocated via the kvstore.
func AllocateIdentity(ctx context.Context, owner IdentityAllocatorOwner, lbls labels.Labels) (id *identity.Identity, allocated bool, err error) {
	// Notify the owner of the newly added identities so that the
	// cached identities can be updated ASAP, rather than just
	// relying on the kv-store update events.
	defer func() {
		if err == nil && owner != nil && allocated {
			added := IdentityCache{
				id.ID: id.LabelArray,
			}
			owner.UpdateIdentities(added, nil)
		}
	}()
	log.WithFields(logrus.Fields{
		logfields.IdentityLabels: lbls.String(),
	}).Debug("Resolving identity")

	// If there is only one label with the "reserved" source and a well-known
	// key, use the well-known identity for that key.
	if reservedIdentity := LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		log.WithFields(logrus.Fields{
			logfields.Identity:       reservedIdentity.ID,
			logfields.IdentityLabels: lbls.String(),
			"isNew":                  false,
		}).Debug("Resolved reserved identity")
		return reservedIdentity, false, nil
	}

	if !identity.RequiresGlobalIdentity(lbls) && localIdentities != nil {
		return localIdentities.lookupOrCreate(lbls)
	}

	// This will block until the kvstore can be accessed and all identities
	// were succesfully synced
	WaitForInitialIdentities(ctx)

	if IdentityAllocator == nil {
		return nil, false, fmt.Errorf("allocator not initialized")
	}

	idp, isNew, err := IdentityAllocator.Allocate(ctx, globalIdentity{lbls.LabelArray()})
	if err != nil {
		return nil, false, err
	}

	log.WithFields(logrus.Fields{
		logfields.Identity:       idp,
		logfields.IdentityLabels: lbls.String(),
		"isNew":                  isNew,
	}).Debug("Resolved identity")

	return identity.NewIdentity(identity.NumericIdentity(idp), lbls), isNew, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func Release(ctx context.Context, owner IdentityAllocatorOwner, id *identity.Identity) (bool, error) {
	// Ignore reserved identities.
	if id.IsReserved() {
		return false, nil
	}

	if !identity.RequiresGlobalIdentity(id.Labels) && localIdentities != nil {
		lastUse := localIdentities.release(id)
		// Notify release of locally managed identities on last use
		if owner != nil && lastUse {
			deleted := IdentityCache{
				id.ID: id.LabelArray,
			}
			owner.UpdateIdentities(nil, deleted)
		}
		return lastUse, nil
	}

	// This will block until the kvstore can be accessed and all identities
	// were succesfully synced
	WaitForInitialIdentities(ctx)

	if IdentityAllocator == nil {
		return false, fmt.Errorf("allocator not initialized")
	}

	// Rely on the eventual Kv-Store events for delete
	// notifications of kv-store allocated identities. Even if an
	// ID is no longer used locally, it may still be used by
	// remote nodes, so we can't rely on the locally computed
	// "lastUse".
	return IdentityAllocator.Release(ctx, globalIdentity{id.LabelArray})
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func ReleaseSlice(ctx context.Context, owner IdentityAllocatorOwner, identities []*identity.Identity) error {
	var err error
	for _, id := range identities {
		if id == nil {
			continue
		}
		_, err2 := Release(ctx, owner, id)
		if err2 != nil {
			log.WithError(err2).WithFields(logrus.Fields{
				logfields.Identity: id,
			}).Error("Failed to release identity")
			err = err2
		}
	}
	return err
}

// WatchRemoteIdentities starts watching for identities in another kvstore and
// syncs all identities to the local identity cache.
func WatchRemoteIdentities(backend kvstore.BackendOperations) *allocator.RemoteCache {
	<-identityAllocatorInitialized
	return IdentityAllocator.WatchRemoteKVStore(backend, IdentitiesPath)
}
