// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"path"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
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
)

var (
	// IdentitiesPath is the path to where identities are stored in the
	// key-value store.
	IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")
)

// CachingIdentityAllocator manages the allocation of identities for both
// global and local identities.
type CachingIdentityAllocator struct {
	// IdentityAllocator is an allocator for security identities from the
	// kvstore.
	IdentityAllocator *allocator.Allocator

	// globalIdentityAllocatorInitialized is closed whenever the global identity
	// allocator is initialized.
	globalIdentityAllocatorInitialized chan struct{}

	localIdentities *localIdentityCache

	identitiesPath string

	// This field exists is to hand out references that are either for sending
	// and receiving. It should not be used directly without converting it first
	// to a AllocatorEventSendChan or AllocatorEventRecvChan.
	events  allocator.AllocatorEventChan
	watcher identityWatcher

	// setupMutex synchronizes InitIdentityAllocator() and Close()
	setupMutex lock.Mutex

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
	// A possible previously used numeric identity for these labels can be passed
	// in as the last parameter; identity.InvalidIdentity must be passed if no
	// previous numeric identity exists.
	AllocateIdentity(context.Context, labels.Labels, bool, identity.NumericIdentity) (*identity.Identity, bool, error)

	// Release is the reverse operation of AllocateIdentity() and releases the
	// specified identity.
	Release(context.Context, *identity.Identity, bool) (released bool, err error)

	// ReleaseSlice is the slice variant of Release().
	ReleaseSlice(context.Context, []*identity.Identity) error

	// LookupIdentityByID returns the identity that corresponds to the given
	// labels.
	LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity

	// LookupIdentityByID returns the identity that corresponds to the given
	// numeric identity.
	LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity

	// GetIdentityCache returns the current cache of identities that the
	// allocator has allocated. The caller should not modify the resulting
	// identities by pointer.
	GetIdentityCache() IdentityCache

	// GetIdentities returns a copy of the current cache of identities.
	GetIdentities() IdentitiesModel

	// AllocateCIDRsForIPs attempts to allocate identities for a list of
	// CIDRs. If any allocation fails, all allocations are rolled back and
	// the error is returned. When an identity is freshly allocated for a
	// CIDR, it is added to the ipcache if 'newlyAllocatedIdentities' is
	// 'nil', otherwise the newly allocated identities are placed in
	// 'newlyAllocatedIdentities' and it is the caller's responsibility to
	// upsert them into ipcache by calling UpsertGeneratedIdentities().
	//
	// Upon success, the caller must also arrange for the resulting identities to
	// be released via a subsequent call to ReleaseCIDRIdentitiesByID().
	//
	// The implementation for this function currently lives in pkg/ipcache.
	AllocateCIDRsForIPs(ips []net.IP, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error)

	// ReleaseCIDRIdentitiesByID() is a wrapper for ReleaseSlice() that
	// also handles ipcache entries.
	ReleaseCIDRIdentitiesByID(context.Context, []identity.NumericIdentity)
}

// InitIdentityAllocator creates the global identity allocator. Only the first
// invocation of this function will have an effect. The Caller must have
// initialized well known identities before calling this (by calling
// identity.InitWellKnownIdentities()).
// The client is only used by the CRD identity allocator currently.
// Returns a channel which is closed when initialization of the allocator is
// completed.
// TODO: identity backends are initialized directly in this function, pulling
// in dependencies on kvstore and k8s. It would be better to decouple this,
// since the backends are an interface.
func (m *CachingIdentityAllocator) InitIdentityAllocator(client clientset.Interface) <-chan struct{} {
	m.setupMutex.Lock()
	defer m.setupMutex.Unlock()

	if m.IdentityAllocator != nil {
		log.Panic("InitIdentityAllocator() in succession without calling Close()")
	}

	log.Info("Initializing identity allocator")

	minID := idpool.ID(identity.MinimalAllocationIdentity)
	maxID := idpool.ID(identity.MaximumAllocationIdentity)

	log.WithFields(map[string]interface{}{
		"min":        minID,
		"max":        maxID,
		"cluster-id": option.Config.ClusterID,
	}).Info("Allocating identities between range")

	// In the case of the allocator being closed, we need to create a new events channel
	// and start a new watch.
	if m.events == nil {
		m.events = make(allocator.AllocatorEventChan, eventsQueueSize)
		m.watcher.watch(m.events)
	}

	// Asynchronously set up the global identity allocator since it connects
	// to the kvstore.
	go func(owner IdentityAllocatorOwner, events allocator.AllocatorEventSendChan, minID, maxID idpool.ID) {
		m.setupMutex.Lock()
		defer m.setupMutex.Unlock()

		var (
			backend allocator.Backend
			err     error
		)

		switch option.Config.IdentityAllocationMode {
		case option.IdentityAllocationModeKVstore:
			log.Debug("Identity allocation backed by KVStore")
			backend, err = kvstoreallocator.NewKVStoreBackend(m.identitiesPath, owner.GetNodeSuffix(), &key.GlobalIdentity{}, kvstore.Client())
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize kvstore backend for identity allocation")
			}

		case option.IdentityAllocationModeCRD:
			log.Debug("Identity allocation backed by CRD")
			backend, err = identitybackend.NewCRDBackend(identitybackend.CRDBackendConfiguration{
				Store:   nil,
				Client:  client,
				KeyFunc: (&key.GlobalIdentity{}).PutKeyFromMap,
			})
			if err != nil {
				log.WithError(err).Fatal("Unable to initialize Kubernetes CRD backend for identity allocation")
			}

		default:
			log.Fatalf("Unsupported identity allocation mode %s", option.Config.IdentityAllocationMode)
		}

		a, err := allocator.NewAllocator(&key.GlobalIdentity{}, backend,
			allocator.WithMax(maxID), allocator.WithMin(minID),
			allocator.WithEvents(events),
			allocator.WithMasterKeyProtection(),
			allocator.WithPrefixMask(idpool.ID(option.Config.ClusterID<<identity.ClusterIDShift)))
		if err != nil {
			log.WithError(err).Fatalf("Unable to initialize Identity Allocator with backend %s", option.Config.IdentityAllocationMode)
		}

		m.IdentityAllocator = a
		close(m.globalIdentityAllocatorInitialized)
	}(m.owner, m.events, minID, maxID)

	return m.globalIdentityAllocatorInitialized
}

const eventsQueueSize = 1024

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
		owner: owner,
	}

	m := &CachingIdentityAllocator{
		globalIdentityAllocatorInitialized: make(chan struct{}),
		owner:                              owner,
		identitiesPath:                     IdentitiesPath,
		watcher:                            watcher,
		events:                             make(allocator.AllocatorEventChan, eventsQueueSize),
	}
	m.watcher.watch(m.events)

	// Local identity cache can be created synchronously since it doesn't
	// rely upon any external resources (e.g., external kvstore).
	m.localIdentities = newLocalIdentityCache(identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity, m.events)

	return m
}

// Close closes the identity allocator
func (m *CachingIdentityAllocator) Close() {
	m.setupMutex.Lock()
	defer m.setupMutex.Unlock()

	select {
	case <-m.globalIdentityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if m.IdentityAllocator == nil {
			log.Error("Close() called without calling InitIdentityAllocator() first")
			return
		}
	}

	m.IdentityAllocator.Delete()
	if m.events != nil {
		// Have the now only remaining writing party close the events channel,
		// to ensure we don't panic with 'send on closed channel'.
		m.localIdentities.close()
		m.events = nil
	}

	m.IdentityAllocator = nil
	m.globalIdentityAllocatorInitialized = make(chan struct{})
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
// allocated via the kvstore or via the local identity allocator.
// A possible previously used numeric identity for these labels can be passed
// in as the 'oldNID' parameter; identity.InvalidIdentity must be passed if no
// previous numeric identity exists.
func (m *CachingIdentityAllocator) AllocateIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error) {
	isNewLocally := false

	// Notify the owner of the newly added identities so that the
	// cached identities can be updated ASAP, rather than just
	// relying on the kv-store update events.
	defer func() {
		if err == nil {
			if allocated || isNewLocally {
				if id.ID.HasLocalScope() {
					metrics.Identity.WithLabelValues(identity.NodeLocalIdentityType).Inc()
				} else if id.ID.IsReservedIdentity() {
					metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Inc()
				} else {
					metrics.Identity.WithLabelValues(identity.ClusterLocalIdentityType).Inc()
				}
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
		return m.localIdentities.lookupOrCreate(lbls, oldNID)
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

	idp, isNew, isNewLocally, err := m.IdentityAllocator.Allocate(ctx, &key.GlobalIdentity{LabelArray: lbls.LabelArray()})
	if err != nil {
		return nil, false, err
	}
	if idp > identity.MaxNumericIdentity {
		return nil, false, fmt.Errorf("%d: numeric identity too large", idp)
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
func (m *CachingIdentityAllocator) Release(ctx context.Context, id *identity.Identity, notifyOwner bool) (released bool, err error) {
	defer func() {
		if released {
			if id.ID.HasLocalScope() {
				metrics.Identity.WithLabelValues(identity.NodeLocalIdentityType).Dec()
			} else if id.ID.IsReservedIdentity() {
				metrics.Identity.WithLabelValues(identity.ReservedIdentityType).Dec()
			} else {
				metrics.Identity.WithLabelValues(identity.ClusterLocalIdentityType).Dec()
			}
		}
		if m.owner != nil && released && notifyOwner {
			deleted := IdentityCache{
				id.ID: id.LabelArray,
			}
			m.owner.UpdateIdentities(nil, deleted)
		}
	}()

	// Ignore reserved identities.
	if id.IsReserved() {
		return false, nil
	}

	if !identity.RequiresGlobalIdentity(id.Labels) {
		return m.localIdentities.release(id), nil
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
	return m.IdentityAllocator.Release(ctx, &key.GlobalIdentity{LabelArray: id.LabelArray})
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func (m *CachingIdentityAllocator) ReleaseSlice(ctx context.Context, identities []*identity.Identity) error {
	var err error
	for _, id := range identities {
		if id == nil {
			continue
		}
		_, err2 := m.Release(ctx, id, false)
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
// syncs all identities to the local identity cache. remoteName must be unique,
// unless replacing the kvstore for an existing remote.
func (m *CachingIdentityAllocator) WatchRemoteIdentities(remoteName string, backend kvstore.BackendOperations) (*allocator.RemoteCache, error) {
	<-m.globalIdentityAllocatorInitialized

	remoteAllocatorBackend, err := kvstoreallocator.NewKVStoreBackend(m.identitiesPath, m.owner.GetNodeSuffix(), &key.GlobalIdentity{}, backend)
	if err != nil {
		return nil, fmt.Errorf("error setting up remote allocator backend: %s", err)
	}

	remoteAlloc, err := allocator.NewAllocator(&key.GlobalIdentity{}, remoteAllocatorBackend, allocator.WithEvents(m.IdentityAllocator.GetEvents()), allocator.WithoutGC())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize remote Identity Allocator: %s", err)
	}

	return m.IdentityAllocator.WatchRemoteKVStore(remoteName, remoteAlloc), nil
}

func (m *CachingIdentityAllocator) RemoveRemoteIdentities(name string) {
	if m.IdentityAllocator != nil {
		m.IdentityAllocator.RemoveRemoteKVStore(name)
	}
}
