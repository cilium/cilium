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

var (
	// IdentitiesPath is the path to where identities are stored in the
	// key-value store.
	IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")
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

// CachingIdentityAllocator manages the allocation of identities for both
// global and local identities.
type CachingIdentityAllocator struct {
	// IdentityAllocator is an allocator for security identities from the
	// kvstore.
	IdentityAllocator *allocator.Allocator

	// globalIdentityAllocatorInitialized is closed whenever the global identity
	// allocator is initialized.
	globalIdentityAllocatorInitialized chan struct{}

	// localIdentityAllocatorInitialized is closed whenever the local identity
	// allocator is initialized.
	localIdentityAllocatorInitialized chan struct{}

	localIdentities *localIdentityCache

	identitiesPath string

	// setupMutex synchronizes InitIdentityAllocator() and Close()
	setupMutex lock.Mutex

	watcher identityWatcher

	owner IdentityAllocatorOwner
}

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

// IdentityAllocator is any type which is responsible for allocating security
// identities based of sets of labels, and caching information about identities
// locally.
type IdentityAllocator interface {
	// WaitForInitialGlobalIdentities waits for the initial set of global
	// security identities to have been received.
	WaitForInitialGlobalIdentities(context.Context) error

	// AllocateIdentity allocates an identity described by the specified labels.
	AllocateIdentity(context.Context, labels.Labels, bool) (*identity.Identity, bool, error)

	// Release is the reverse operation of AllocateIdentity() and releases the
	// specified identity.
	Release(context.Context, *identity.Identity) (released bool, err error)

	// LookupIdentityByID returns the identity that corresponds to the given
	// numeric identity.
	LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity
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
func (m *CachingIdentityAllocator) InitIdentityAllocator(client clientset.Interface, identityStore cache.Store) <-chan struct{} {
	m.setupMutex.Lock()
	defer m.setupMutex.Unlock()

	if m.IdentityAllocator != nil {
		log.Panic("InitIdentityAllocator() in succession without calling Close()")
	}

	log.Info("Initializing identity allocator")

	// Local identity cache can be created synchronously since it doesn't
	// rely upon any external resources (e.g., external kvstore).
	events := make(allocator.AllocatorEventChan, 1024)
	m.localIdentities = newLocalIdentityCache(1, 0xFFFFFF, events)
	close(m.localIdentityAllocatorInitialized)

	minID := idpool.ID(identity.MinimalAllocationIdentity)
	maxID := idpool.ID(identity.MaximumAllocationIdentity)

	// It is important to start listening for events before calling
	// NewAllocator() as it will emit events while filling the
	// initial cache
	m.watcher.watch(events)

	// Asynchronously set up the global identity allocator since it connects
	// to the kvstore.
	go func(owner IdentityAllocatorOwner, evs allocator.AllocatorEventChan, minID, maxID idpool.ID) {
		m.setupMutex.Lock()
		defer m.setupMutex.Unlock()

		var (
			backend allocator.Backend
			err     error
		)

		switch option.Config.IdentityAllocationMode {
		case option.IdentityAllocationModeKVstore:
			log.Debug("Identity allocation backed by KVStore")
			backend, err = kvstoreallocator.NewKVStoreBackend(m.identitiesPath, owner.GetNodeSuffix(), GlobalIdentity{}, kvstore.Client())
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

		m.IdentityAllocator = a
		close(m.globalIdentityAllocatorInitialized)
	}(m.owner, events, minID, maxID)

	return m.globalIdentityAllocatorInitialized
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

// NewCachingIdentityAllocator creates a new instance of an
// CachingIdentityAllocator.
func NewCachingIdentityAllocator(owner IdentityAllocatorOwner) *CachingIdentityAllocator {
	watcher := identityWatcher{
		stopChan: make(chan struct{}),
		owner:    owner,
	}

	mgr := &CachingIdentityAllocator{
		globalIdentityAllocatorInitialized: make(chan struct{}),
		localIdentityAllocatorInitialized:  make(chan struct{}),
		owner:                              owner,
		identitiesPath:                     IdentitiesPath,
		watcher:                            watcher,
	}
	return mgr
}

// Close closes the identity allocator and allows to call
// InitIdentityAllocator() again.
func (m *CachingIdentityAllocator) Close() {
	m.setupMutex.Lock()
	defer m.setupMutex.Unlock()

	select {
	case <-m.globalIdentityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if m.IdentityAllocator == nil {
			log.Panic("Close() called without calling InitIdentityAllocator() first")
		}
	}

	select {
	case <-m.localIdentityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if m.IdentityAllocator == nil {
			log.Panic("Close() called without calling InitIdentityAllocator() first")
		}
	}

	m.IdentityAllocator.Delete()
	m.watcher.stop()
	m.IdentityAllocator = nil
	m.globalIdentityAllocatorInitialized = make(chan struct{})
	m.localIdentityAllocatorInitialized = make(chan struct{})
	m.localIdentities = nil
}

// WaitForInitialGlobalIdentities waits for the initial set of global security
// identities to have been received and populated into the allocator cache.
func (m *CachingIdentityAllocator) WaitForInitialGlobalIdentities(ctx context.Context) error {
	select {
	case <-m.globalIdentityAllocatorInitialized:
	case <-ctx.Done():
		return fmt.Errorf("initial global identity sync was cancelled: %s", ctx.Err())
	}

	return m.IdentityAllocator.WaitForInitialSync(ctx)
}

// AllocateIdentity allocates an identity described by the specified labels. If
// an identity for the specified set of labels already exist, the identity is
// re-used and reference counting is performed, otherwise a new identity is
// allocated via the kvstore.
func (m *CachingIdentityAllocator) AllocateIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool) (id *identity.Identity, allocated bool, err error) {
	isNewLocally := false

	// Notify the owner of the newly added identities so that the
	// cached identities can be updated ASAP, rather than just
	// relying on the kv-store update events.
	defer func() {
		if err == nil {
			if allocated || isNewLocally {
				metrics.Identity.Inc()
			}

			if allocated && notifyOwner {
				added := IdentityCache{
					id.ID: id.LabelArray,
				}
				m.owner.UpdateIdentities(added, nil)
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
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
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
		<-m.localIdentityAllocatorInitialized
		return m.localIdentities.lookupOrCreate(lbls)
	}

	// This will block until the kvstore can be accessed and all identities
	// were successfully synced
	err = m.WaitForInitialGlobalIdentities(ctx)
	if err != nil {
		return nil, false, err
	}

	if m.IdentityAllocator == nil {
		return nil, false, fmt.Errorf("allocator not initialized")
	}

	idp, isNew, isNewLocally, err := m.IdentityAllocator.Allocate(ctx, GlobalIdentity{lbls.LabelArray()})
	if err != nil {
		return nil, false, err
	}

	if option.Config.Debug {
		log.WithFields(logrus.Fields{
			logfields.Identity:       idp,
			logfields.IdentityLabels: lbls.String(),
			"isNew":                  isNew,
			"isNewLocally":           isNewLocally,
		}).Debug("Resolved identity")
	}

	return identity.NewIdentity(identity.NumericIdentity(idp), lbls), isNew, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func (m *CachingIdentityAllocator) Release(ctx context.Context, id *identity.Identity) (released bool, err error) {
	defer func() {
		if released {
			metrics.Identity.Dec()
		}
	}()

	// Ignore reserved identities.
	if id.IsReserved() {
		return false, nil
	}

	if !identity.RequiresGlobalIdentity(id.Labels) {
		<-m.localIdentityAllocatorInitialized
		lastUse := m.localIdentities.release(id)
		// Notify release of locally managed identities on last use
		if m.owner != nil && lastUse {
			deleted := IdentityCache{
				id.ID: id.LabelArray,
			}
			m.owner.UpdateIdentities(nil, deleted)
		}
		return lastUse, nil
	}

	// This will block until the kvstore can be accessed and all identities
	// were successfully synced
	err = m.WaitForInitialGlobalIdentities(ctx)
	if err != nil {
		return false, err
	}

	if m.IdentityAllocator == nil {
		return false, fmt.Errorf("allocator not initialized")
	}

	// Rely on the eventual Kv-Store events for delete
	// notifications of kv-store allocated identities. Even if an
	// ID is no longer used locally, it may still be used by
	// remote nodes, so we can't rely on the locally computed
	// "lastUse".
	return m.IdentityAllocator.Release(ctx, GlobalIdentity{id.LabelArray})
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func (m *CachingIdentityAllocator) ReleaseSlice(ctx context.Context, owner IdentityAllocatorOwner, identities []*identity.Identity) error {
	var err error
	for _, id := range identities {
		if id == nil {
			continue
		}
		_, err2 := m.Release(ctx, id)
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
func (m *CachingIdentityAllocator) WatchRemoteIdentities(backend kvstore.BackendOperations) (*allocator.RemoteCache, error) {
	<-m.globalIdentityAllocatorInitialized

	remoteAllocatorBackend, err := kvstoreallocator.NewKVStoreBackend(m.identitiesPath, m.owner.GetNodeSuffix(), GlobalIdentity{}, backend)
	if err != nil {
		return nil, fmt.Errorf("Error setting up remote allocator backend: %s", err)
	}

	remoteAlloc, err := allocator.NewAllocator(GlobalIdentity{}, remoteAllocatorBackend, allocator.WithEvents(m.IdentityAllocator.GetEvents()))
	if err != nil {
		return nil, fmt.Errorf("Unable to initialize remote Identity Allocator: %s", err)
	}

	return m.IdentityAllocator.WatchRemoteKVStore(remoteAlloc), nil
}
