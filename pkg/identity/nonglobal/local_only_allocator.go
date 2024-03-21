// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nonglobal

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "non-global-identity")
)

type LocalOnlyCachingIDAllocator struct {
	*idcache.LocalCacheAllocator

	context          context.Context
	tempIDAllocator  *TempSecIDAllocator
	ciliumIdentities resource.Resource[*capi_v2.CiliumIdentity]

	// globalIdentityAllocatorInitialized is closed whenever the global identity
	// allocator is initialized.
	globalIdentityAllocatorInitialized chan struct{}

	identitiesPath string

	events     allocator.AllocatorEventChan
	watcher    idcache.IdentityWatcher
	cidTracker *cidEventTracker

	idObserver *observer

	setupMutex lock.Mutex
	stopChan   chan struct{}

	endpointListerFunc func() []*endpoint.Endpoint
	endpointQueue      workqueue.RateLimitingInterface
}

// func NewLocalOnlyCachingIDAllocator(owner IdentityAllocatorOwner, cidChangeFunc func(cid *v2.CiliumIdentity)) *LocalOnlyCachingIDAllocator {
func NewLocalOnlyCachingIDAllocator(
	ctx context.Context, owner idcache.IdentityAllocatorOwner,
	cidResource resource.Resource[*capi_v2.CiliumIdentity],
	endpointListerFunc func() []*endpoint.Endpoint,
) *LocalOnlyCachingIDAllocator {
	stopChan := make(chan struct{})

	watcher := idcache.IdentityWatcher{
		Owner: owner,
	}

	l := &LocalOnlyCachingIDAllocator{
		context:                            ctx,
		LocalCacheAllocator:                &idcache.LocalCacheAllocator{},
		ciliumIdentities:                   cidResource,
		globalIdentityAllocatorInitialized: make(chan struct{}),
		identitiesPath:                     idcache.IdentitiesPath,
		watcher:                            watcher,
		events:                             make(allocator.AllocatorEventChan, 1024),
		cidTracker:                         newCIDEventTracker(),
		idObserver:                         NewIDObserver(ctx, stopChan, cidResource),
		endpointListerFunc:                 endpointListerFunc,
		stopChan:                           stopChan,
	}
	l.Owner = owner

	l.initEndpointQueue()
	l.watcher.Watch(l.events)

	// Local identity cache can be created synchronously since it doesn't
	// rely upon any external resources (e.g., external kvstore).
	l.LocalIdentities = idcache.NewLocalIdentityCache(identity.IdentityScopeLocal, identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity, l.events)
	l.LocalNodeIdentities = idcache.NewLocalIdentityCache(identity.IdentityScopeRemoteNode, identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity, l.events)

	l.tempIDAllocator = NewTempSecIDAllocator(endpointListerFunc)

	return l
}

func (l *LocalOnlyCachingIDAllocator) InitIdentityAllocator(client clientset.Interface) <-chan struct{} {
	l.setupMutex.Lock()
	defer l.setupMutex.Unlock()

	if l.isGlobalIdentityAllocatorInitialized() {
		log.Warningf("InitIdentityAllocator called when LocalOnlyCachingIDAllocator is already running")
		return l.globalIdentityAllocatorInitialized
	}

	go l.processCiliumIdentityEvents(l.context)
	go l.runEndpointWorker()
	go l.tempIDAllocator.StartPeriodicGC(l.stopChan)

	close(l.globalIdentityAllocatorInitialized)
	return l.globalIdentityAllocatorInitialized
}

// WaitForInitialGlobalIdentities waits for the initial set of global security
// identities to have been received and populated into the allocator cache.
func (l *LocalOnlyCachingIDAllocator) WaitForInitialGlobalIdentities(ctx context.Context) error {
	select {
	case <-l.globalIdentityAllocatorInitialized:
	case <-ctx.Done():
		return fmt.Errorf("initial global identity sync was cancelled: %s", ctx.Err())
	}

	return nil
}

// AllocateIdentity allocates an identity described by the specified labels. If
// an identity for the specified set of labels already exist, the identity is
// re-used and reference counting is performed, otherwise a new identity is
// allocated via the kvstore or via the local identity allocator.
// A possible previously used numeric identity for these labels can be passed
// in as the 'oldNID' parameter; identity.InvalidIdentity must be passed if no
// previous numeric identity exists.
func (l *LocalOnlyCachingIDAllocator) AllocateIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error) {
	id, allocated, completed, err := l.AllocateLocalIdentity(ctx, lbls, notifyOwner, oldNID)
	if err != nil || completed {
		return id, allocated, err
	}

	// This doesn't allocate global IDs anymore.
	// The above part is required for IPCache to allocate CIDRs for CEPs.
	selectedID := l.lookupGlobalOrTempIDByLabels(lbls)
	allocated = false
	if selectedID == nil {
		// Assign a temp identity when a real global identity is not yet assigned.
		selectedID, err = l.tempIDAllocator.FindOrCreateTempID(lbls)
		if err != nil {
			return nil, false, err
		}
		allocated = true
	}

	return selectedID, allocated, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func (l *LocalOnlyCachingIDAllocator) Release(ctx context.Context, id *identity.Identity, notifyOwner bool) (released bool, err error) {
	released, _, err = l.ReleaseLocalIdentity(ctx, id, notifyOwner)
	// This doesn't allocate global IDs anymore.
	// The above part is required for IPCache to allocate CIDRs for CEPs.
	// What about releasing the ID allocated by the Global Temp ID Allocator.
	return released, err
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func (l *LocalOnlyCachingIDAllocator) ReleaseSlice(ctx context.Context, identities []*identity.Identity) error {
	var err error
	for _, id := range identities {
		if id == nil {
			continue
		}
		_, err2 := l.Release(ctx, id, false)
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
func (l *LocalOnlyCachingIDAllocator) WatchRemoteIdentities(remoteName string, backend kvstore.BackendOperations, cachedPrefix bool) (*allocator.RemoteCache, error) {
	// Watching remote identities doesn't work when operator is managing global
	// security identities. Operators need to be connected to each other then.
	return nil, fmt.Errorf("cannot watch remote identities when kvstore is not used and operator is managing global security identities")
}

// GetIdentityCache returns a cache of all known identities
func (l *LocalOnlyCachingIDAllocator) GetIdentityCache() idcache.IdentityCache {
	cache := l.GetLocalIdentityCache()

	if !l.isGlobalIdentityAllocatorInitialized() {
		return cache
	}

	cidStore, _ := l.ciliumIdentities.Store(l.context)
	for _, cid := range cidStore.List() {
		idInt, err := strconv.Atoi(cid.Name)
		if err != nil {
			continue
		}

		id := identity.NumericIdentity(idInt)
		lblArray := labels.Map2Labels(cid.SecurityLabels, "").LabelArray()
		cache[id] = lblArray
	}

	return cache
}

// GetIdentities returns all known identities
func (l *LocalOnlyCachingIDAllocator) GetIdentities() idcache.IdentitiesModel {
	identities := l.GetLocalIdentities()

	if err := l.WaitForInitialGlobalIdentities(context.TODO()); err != nil {
		log.Warningf("GetIdentities failed because global identity cache is not initialized")
		return identities
	}

	cidStore, _ := l.ciliumIdentities.Store(l.context)
	for _, cid := range cidStore.List() {
		idInt, err := strconv.Atoi(cid.Name)
		if err != nil {
			continue
		}

		lblArray := labels.Map2Labels(cid.SecurityLabels, "").LabelArray()
		id := identity.NewIdentityFromLabelArray(identity.NumericIdentity(idInt), lblArray)
		identities = append(identities, identitymodel.CreateModel(id))
	}

	return identities
}

func (l *LocalOnlyCachingIDAllocator) isGlobalIdentityAllocatorInitialized() bool {
	cidStore, err := l.ciliumIdentities.Store(l.context)

	select {
	case <-l.globalIdentityAllocatorInitialized:
		if err != nil {
			return false
		}
		if cidStore == nil {
			return false
		}
		return true
	default:
		return false
	}
}

// LookupIdentity looks up the identity by its labels but does not create it.
// This function will first search through the local cache, then the caches for
// remote kvstores and finally fall back to the main kvstore.
// May return nil for lookups if the allocator has not yet been synchronized.
func (l *LocalOnlyCachingIDAllocator) LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity {
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		return reservedIdentity
	}

	if !identity.RequiresGlobalIdentity(lbls) {
		return l.LocalIdentities.Lookup(lbls)
	}

	if !l.isGlobalIdentityAllocatorInitialized() {
		return nil
	}

	return l.lookupGlobalOrTempIDByLabels(lbls)
}

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache, then the caches for remote kvstores and
// finally fall back to the main kvstore
// May return nil for lookups if the allocator has not yet been synchronized.
func (l *LocalOnlyCachingIDAllocator) LookupIdentityByID(ctx context.Context, numID identity.NumericIdentity) *identity.Identity {
	if numID == identity.IdentityUnknown {
		return identity.UnknownIdentity
	}

	if id := identity.LookupReservedIdentity(numID); id != nil {
		return id
	}

	if numID.HasLocalScope() {
		return l.LocalIdentities.LookupByID(numID)
	}

	if !l.isGlobalIdentityAllocatorInitialized() {
		return nil
	}

	cid := l.getCIDByKey(numID.String())
	if cid != nil {
		lblArray := labels.Map2Labels(cid.SecurityLabels, "").LabelArray()
		return identity.NewIdentityFromLabelArray(numID, lblArray)
	}

	if identity.IsTempID(numID) {
		id, _ := l.tempIDAllocator.LookupByID(numID)
		return id
	}

	return nil
}

func (l *LocalOnlyCachingIDAllocator) RemoveRemoteIdentities(name string) {
	// LocalOnlyCachingIDAllocator doesn't handle remote identities.
	return
}

func (l *LocalOnlyCachingIDAllocator) Close() {
	l.setupMutex.Lock()
	l.endpointQueue.ShutDown()
	defer l.setupMutex.Unlock()
	close(l.stopChan)
}

func (l *LocalOnlyCachingIDAllocator) WithholdLocalIdentities(nids []identity.NumericIdentity) {
	l.WithholdLocalIDs(nids)
}

func (l *LocalOnlyCachingIDAllocator) UnwithholdLocalIdentities(nids []identity.NumericIdentity) {
	l.UnwithholdLocalIDs(nids)
}

// Observe the identity changes. Conforms to stream.Observable.
// Replays the current state of the cache when subscribing.
func (l *LocalOnlyCachingIDAllocator) Observe(ctx context.Context, next func(idcache.IdentityChange), complete func(error)) {
	// This short-lived go routine serves the purpose of waiting for the global identity allocator becoming ready
	// before starting to observe the underlying allocator for changes.
	// m.IdentityAllocator is backed by a stream.FuncObservable, that will start its own
	// go routine. Therefore, the current go routine will stop and free the lock on the setupMutex after the registration.
	go func() {
		if err := l.WaitForInitialGlobalIdentities(ctx); err != nil {
			complete(ctx.Err())
			return
		}

		l.setupMutex.Lock()
		defer l.setupMutex.Unlock()

		if l.idObserver == nil {
			complete(errors.New("allocator no longer initialized"))
			return
		}

		// Observe the underlying allocator for changes and map the events to identities.
		stream.Map[allocator.AllocatorChange, idcache.IdentityChange](
			l.idObserver, //l.IdentityAllocator,
			func(change allocator.AllocatorChange) idcache.IdentityChange {
				return idcache.IdentityChange{
					Kind:   idcache.IdentityChangeKind(change.Kind),
					ID:     identity.NumericIdentity(change.ID),
					Labels: idcache.MapLabels(change.Key),
				}
			},
		).Observe(ctx, next, complete)
	}()
}
