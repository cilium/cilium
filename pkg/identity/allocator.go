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
	"path"
	"sync"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	// MaxIdentity is the maximum identity value
	MaxIdentity = ^uint16(0)
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
		a, err := allocator.NewAllocator(IdentitiesPath, globalIdentity{},
			allocator.WithMax(maxID), allocator.WithMin(minID),
			allocator.WithSuffix(owner.GetNodeSuffix()))
		if err != nil {
			log.WithError(err).Fatal("Unable to initialize identity allocator")
		}

		identityAllocator = a

		go identityWatcher(owner)
	})
}

// AllocateIdentity allocates an identity described by the specified labels. If
// an identity for the specified set of labels already exist, the identity is
// re-used and reference counting is performed, otherwise a new identity is
// allocated via the kvstore.
func AllocateIdentity(lbls labels.Labels) (*Identity, bool, error) {
	log.WithFields(logrus.Fields{
		logfields.IdentityLabels: lbls.String(),
	}).Debug("Resolving identity")

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
	return identityAllocator.Release(globalIdentity{id.Labels})
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func ReleaseSlice(identities []*Identity) error {
	var err error
	for _, id := range identities {
		if err = id.Release(); err != nil {
			log.WithFields(logrus.Fields{
				logfields.Identity: id,
			}).Error("Failed to release identity")
		}
	}
	return err
}
