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

package identity

import (
	"fmt"
	"path"
	"sync"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

// globalIdentity is the structure used to store an identity in the kvstore
type globalIdentity struct {
	labels.Labels
}

// GetKey() encodes a globalIdentity as string
func (gi globalIdentity) GetKey() string {
	return kvstore.Encode(gi.SortedList())
}

// PutKey() decides a globalIdentity from its string representation
func (gi globalIdentity) PutKey(v string) (allocator.AllocatorKey, error) {
	b, err := kvstore.Decode(v)
	if err != nil {
		return nil, err
	}

	return globalIdentity{labels.NewLabelsFromSortedList(string(b))}, nil
}

var (
	setupOnce         sync.Once
	identityAllocator *allocator.Allocator

	// IdentitiesPath is the path to where identities are stored in the key-value
	// store.
	IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")
)

// IdentityAllocatorOwner is the interface the owner of an identity allocator
// must implement
type IdentityAllocatorOwner interface {
	// TriggerPolicyUpdates will be called whenever a policy recalculation
	// must be triggered
	TriggerPolicyUpdates(force bool) *sync.WaitGroup

	// GetSuffix must return the node specific suffix to use
	GetNodeSuffix() string
}

// InitIdentityAllocator creates the the identity allocator. Only the first
// invocation of this function will have an effect.
func InitIdentityAllocator(owner IdentityAllocatorOwner) {
	setupOnce.Do(func() {
		log.Info("Initializing identity allocator")

		minID := allocator.ID(MinimalNumericIdentity)
		maxID := allocator.ID(^uint16(0))
		events := make(allocator.AllocatorEventChan, 65536)

		// It is important to start listening for events before calling
		// NewAllocator() as it will emit events while filling the
		// initial cache
		go identityWatcher(owner, events)

		a, err := allocator.NewAllocator(IdentitiesPath, globalIdentity{},
			allocator.WithMax(maxID), allocator.WithMin(minID),
			allocator.WithSuffix(owner.GetNodeSuffix()),
			allocator.WithEvents(events),
			allocator.WithPrefixMask(allocator.ID(option.Config.ClusterID<<option.ClusterIDShift)))
		if err != nil {
			log.WithError(err).Fatal("Unable to initialize identity allocator")
		}

		identityAllocator = a
	})
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
func AllocateIdentity(lbls labels.Labels) (*Identity, bool, error) {
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

	if identityAllocator == nil {
		return nil, false, fmt.Errorf("allocator not initialized")
	}

	id, isNew, err := identityAllocator.Allocate(globalIdentity{lbls})
	if err != nil {
		return nil, false, err
	}

	log.WithFields(logrus.Fields{
		logfields.Identity:       id,
		logfields.IdentityLabels: lbls.String(),
		"isNew":                  isNew,
	}).Debug("Resolved identity")

	return NewIdentity(NumericIdentity(id), lbls), isNew, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func (id *Identity) Release() error {
	// Ignore reserved identities.
	if LookupReservedIdentity(id.ID) != nil {
		return nil
	}

	if identityAllocator == nil {
		return fmt.Errorf("allocator not initialized")
	}

	return identityAllocator.Release(globalIdentity{id.Labels})
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func ReleaseSlice(identities []*Identity) error {
	var err error
	for _, id := range identities {
		if err2 := id.Release(); err2 != nil {
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
	return identityAllocator.WatchRemoteKVStore(backend, IdentitiesPath)
}
