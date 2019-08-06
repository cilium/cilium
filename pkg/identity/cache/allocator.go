// Copyright 2018-2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/idpool"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

// GlobalIdentity is the structure used to store an identity
type GlobalIdentity struct {
	labels.LabelArray
}

// GetKey encodes an Identity as string
func (gi GlobalIdentity) GetKey() (str string) {
	for _, l := range gi.LabelArray {
		str += l.FormatForKVStore()
	}
	return
}

// GetAsMap encodes a GlobalIdentity a map of keys to values. The keys will
// include a source delimted by a ':'. This output is pareable by PutKeyFromMap.
func (gi GlobalIdentity) GetAsMap() map[string]string {
	return gi.StringMap()
}

// PutKey decodes an Identity from its string representation
func (gi GlobalIdentity) PutKey(v string) allocator.AllocatorKey {
	return GlobalIdentity{labels.NewLabelArrayFromSortedList(v)}
}

// PutKeyFromMap decodes an Identity from a map of key to value. Output
// from GetAsMap can be parsed.
// Note: NewLabelArrayFromMap will parse the ':' separated label source from
// the keys because the source parameter is ""
func (gi GlobalIdentity) PutKeyFromMap(v map[string]string) allocator.AllocatorKey {
	return GlobalIdentity{labels.Map2Labels(v, "").LabelArray()}
}

var (
	// IdentityAllocator is an allocator for security identities from the
	// kvstore.
	IdentityAllocator *allocator.Allocator

	// GlobalIdentityAllocatorInitialized is closed whenever the global identity
	// allocator is initialized.
	GlobalIdentityAllocatorInitialized = make(chan struct{})

	// localIdentityAllocatorInitialized is closed whenever the local identity
	// allocator is initialized.
	localIdentityAllocatorInitialized = make(chan struct{})

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
	//
	// The caller is responsible for making sure the same identity
	// is not present in both 'added' and 'deleted', so that they
	// can be processed in either order.
	UpdateIdentities(added, deleted IdentityCache)

	// GetSuffix must return the node specific suffix to use
	GetNodeSuffix() string
}

// InitIdentityAllocator creates the the identity allocator. Only the first
// invocation of this function will have an effect. The Caller must have
// initialized well known identities before calling this (by calling
// identity.InitWellKnownIdentities()).
// client and identityStore are only used by the CRD identity allocator,
// currently, and identityStore may be nil.
// Returns a channel which is closed when initialization of the allocator is
// completed.
// TODO: identity backends are initialized directly in this function, pulling
// in dependencies on kvstore and k8s. It would be better to decouple this,
// since the backends are an interface.
func InitIdentityAllocator(owner IdentityAllocatorOwner, client clientset.Interface, identityStore cache.Store) <-chan struct{} {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	if IdentityAllocator != nil {
		log.Panic("InitIdentityAllocator() in succession without calling Close()")
	}

	log.Info("Initializing identity allocator")

	// Local identity cache can be created synchronously since it doesn't
	// rely upon any external resources (e.g., external kvstore).
	events := make(allocator.AllocatorEventChan, 1024)
	localIdentities = newLocalIdentityCache(1, 0xFFFFFF, events)
	close(localIdentityAllocatorInitialized)

	minID := idpool.ID(identity.MinimalAllocationIdentity)
	maxID := idpool.ID(identity.MaximumAllocationIdentity)

	// It is important to start listening for events before calling
	// NewAllocator() as it will emit events while filling the
	// initial cache
	watcher.watch(owner, events)

	// Asynchronously set up the global identity allocator since it connects
	// to the kvstore.
	go func(owner IdentityAllocatorOwner, evs allocator.AllocatorEventChan, minID, maxID idpool.ID) {
		setupMutex.Lock()
		defer setupMutex.Unlock()

		var (
			backend allocator.Backend
			err     error
		)

		switch option.Config.IdentityAllocationMode {
		case option.IdentityAllocationModeKVstore:
			log.Debug("Identity allocation backed by KVStore")
			backend, err = kvstoreallocator.NewKVStoreBackend(IdentitiesPath, owner.GetNodeSuffix(), GlobalIdentity{})
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize kvstore backend for identity allocation")
			}

		case option.IdentityAllocationModeCRD:
			log.Debug("Identity allocation backed by CRD")
			backend, err = identitybackend.NewCRDBackend(identitybackend.CRDBackendConfiguration{
				NodeName: owner.GetNodeSuffix(),
				Store:    identityStore,
				Client:   client,
				KeyType:  GlobalIdentity{},
			})
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize Kubernetes CRD backend for identity allocation")
			}

		default:
			log.Fatalf("Unsupported identity allocation mode %s", option.Config.IdentityAllocationMode)
		}

		a, err := allocator.NewAllocator(GlobalIdentity{}, backend,
			allocator.WithMax(maxID), allocator.WithMin(minID),
			allocator.WithEvents(events),
			allocator.WithMasterKeyProtection(),
			allocator.WithPrefixMask(idpool.ID(option.Config.ClusterID<<identity.ClusterIDShift)))
		if err != nil {
			log.WithError(err).Fatalf("Unable to initialize Identity Allocator with backend %s", option.Config.IdentityAllocationMode)
		}

		IdentityAllocator = a
		close(GlobalIdentityAllocatorInitialized)
	}(owner, events, minID, maxID)

	return GlobalIdentityAllocatorInitialized
}

// Close closes the identity allocator and allows to call
// InitIdentityAllocator() again
func Close() {
	setupMutex.Lock()
	defer setupMutex.Unlock()

	select {
	case <-GlobalIdentityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if IdentityAllocator == nil {
			log.Panic("Close() called without calling InitIdentityAllocator() first")
		}
	}

	select {
	case <-localIdentityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if IdentityAllocator == nil {
			log.Panic("Close() called without calling InitIdentityAllocator() first")
		}
	}

	IdentityAllocator.Delete()
	watcher.stop()
	IdentityAllocator = nil
	GlobalIdentityAllocatorInitialized = make(chan struct{})
	localIdentityAllocatorInitialized = make(chan struct{})
	localIdentities = nil
}

// WaitForInitialGlobalIdentities waits for the initial set of global security
// identities to have been received and populated into the allocator cache.
func WaitForInitialGlobalIdentities(ctx context.Context) error {
	select {
	case <-GlobalIdentityAllocatorInitialized:
	case <-ctx.Done():
		return fmt.Errorf("initial global identity sync was cancelled: %s", ctx.Err())
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
		if err == nil && allocated {
			metrics.IdentityCount.Inc()
			if owner != nil {
				added := IdentityCache{
					id.ID: id.LabelArray,
				}
				owner.UpdateIdentities(added, nil)
			}
		}
	}()
	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.IdentityLabels: lbls.String(),
		}).Debug("Resolving identity")
	}

	// If there is only one label with the "reserved" source and a well-known
	// key, use the well-known identity for that key.
	if reservedIdentity := LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		if option.Config.Debug {
			log.WithFields(logrus.Fields{
				logfields.Identity:       reservedIdentity.ID,
				logfields.IdentityLabels: lbls.String(),
				"isNew":                  false,
			}).Debug("Resolved reserved identity")
		}
		return reservedIdentity, false, nil
	}

	if !identity.RequiresGlobalIdentity(lbls) {
		<-localIdentityAllocatorInitialized
		return localIdentities.lookupOrCreate(lbls)
	}

	// This will block until the kvstore can be accessed and all identities
	// were successfully synced
	err = WaitForInitialGlobalIdentities(ctx)
	if err != nil {
		return nil, false, err
	}

	if IdentityAllocator == nil {
		return nil, false, fmt.Errorf("allocator not initialized")
	}

	idp, isNew, err := IdentityAllocator.Allocate(ctx, GlobalIdentity{lbls.LabelArray()})
	if err != nil {
		return nil, false, err
	}

	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.Identity:       idp,
			logfields.IdentityLabels: lbls.String(),
			"isNew":                  isNew,
		}).Debug("Resolved identity")
	}

	return identity.NewIdentity(identity.NumericIdentity(idp), lbls), isNew, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func Release(ctx context.Context, owner IdentityAllocatorOwner, id *identity.Identity) (released bool, err error) {
	defer func() {
		if released {
			metrics.IdentityCount.Dec()
		}
	}()

	// Ignore reserved identities.
	if id.IsReserved() {
		return false, nil
	}

	if !identity.RequiresGlobalIdentity(id.Labels) {
		<-localIdentityAllocatorInitialized
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
	// were successfully synced
	err = WaitForInitialGlobalIdentities(ctx)
	if err != nil {
		return false, err
	}

	if IdentityAllocator == nil {
		return false, fmt.Errorf("allocator not initialized")
	}

	// Rely on the eventual Kv-Store events for delete
	// notifications of kv-store allocated identities. Even if an
	// ID is no longer used locally, it may still be used by
	// remote nodes, so we can't rely on the locally computed
	// "lastUse".
	return IdentityAllocator.Release(ctx, GlobalIdentity{id.LabelArray})
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
	<-GlobalIdentityAllocatorInitialized
	return IdentityAllocator.WatchRemoteKVStore(backend, IdentitiesPath)
}
