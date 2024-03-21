// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hybrid

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	idcache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/key"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s"
	capi_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/stream"
	"github.com/cilium/workerpool"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "non-global-identity-allocator")
)

// HybridIDAllocator manages (create, update, delete) local identities, but
// doesn't manage global (cluster-scoped) identities, it only watches global
// identities. It assigns both local and global identities for given labels.
type HybridIDAllocator struct {
	*idcache.LocalCacheAllocator

	ctx context.Context
	wp  *workerpool.WorkerPool

	ciliumIdentities resource.Resource[*capi_v2.CiliumIdentity]
	cidTracker       *cidEventTracker

	// globalIdentityAllocatorInitialized is closed whenever the global identity
	// allocator is initialized.
	globalIdentityAllocatorInitialized chan struct{}

	identitiesPath string

	events     allocator.AllocatorEventChan
	watcher    idcache.IdentityWatcher
	idObserver *observer

	setupMutex lock.Mutex
	stopChan   chan struct{}
}

func NewHybridIDAllocator(
	ctx context.Context,
	owner idcache.IdentityAllocatorOwner,
	cidResource resource.Resource[*capi_v2.CiliumIdentity],
) *HybridIDAllocator {
	stopChan := make(chan struct{})

	watcher := idcache.IdentityWatcher{
		Owner: owner,
	}

	h := &HybridIDAllocator{
		ctx:                                ctx,
		LocalCacheAllocator:                &idcache.LocalCacheAllocator{},
		wp:                                 workerpool.New(1),
		ciliumIdentities:                   cidResource,
		cidTracker:                         newCIDEventTracker(),
		idObserver:                         NewIDObserver(ctx, stopChan, cidResource),
		globalIdentityAllocatorInitialized: make(chan struct{}),
		identitiesPath:                     idcache.IdentitiesPath,
		watcher:                            watcher,
		events:                             make(allocator.AllocatorEventChan, 1024),
		stopChan:                           stopChan,
	}
	h.Owner = owner
	h.watcher.Watch(h.events)

	// Local identity cache can be created synchronously since it doesn't
	// rely upon any external resources (e.g., external kvstore).
	h.LocalIdentities = idcache.NewLocalIdentityCache(identity.IdentityScopeLocal, identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity, h.events)
	h.LocalNodeIdentities = idcache.NewLocalIdentityCache(identity.IdentityScopeRemoteNode, identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity, h.events)

	h.wp.Submit("process-cilium-identity-events", h.processCiliumIdentityEvents)

	return h
}

func (h *HybridIDAllocator) InitIdentityAllocator(client clientset.Interface) <-chan struct{} {
	h.setupMutex.Lock()
	defer h.setupMutex.Unlock()

	if h.isGlobalIdentityAllocatorInitialized() {
		log.Warningf("InitIdentityAllocator called when CachingIdentityAllocator is already running")
		return h.globalIdentityAllocatorInitialized
	}

	close(h.globalIdentityAllocatorInitialized)
	return h.globalIdentityAllocatorInitialized
}

func (h *HybridIDAllocator) processCiliumIdentityEvents(ctx context.Context) error {
	cidHandlerFunc := func(cid *v2.CiliumIdentity, typ kvstore.EventType) {
		eventsChan := h.events
		if eventsChan == nil {
			log.Warning("cilium identity update handler failed because events channel is not initialized")
			return
		}

		idNum, err := strconv.ParseUint(cid.Name, 10, 64)
		if err != nil {
			log.Warningf("cilium identity update handler failed: %v", err)
			return
		}
		id := idpool.ID(idNum)
		keyFunc := (&key.GlobalIdentity{}).PutKeyFromMap
		cidKey := keyFunc(cid.SecurityLabels)

		if h.idObserver != nil {
			if typ == kvstore.EventTypeDelete {
				h.idObserver.getEvent(cid, allocator.AllocatorChangeDelete)
			} else {
				h.idObserver.getEvent(cid, allocator.AllocatorChangeUpsert)
			}
		}

		eventsChan <- allocator.AllocatorEvent{Typ: typ, ID: id, Key: cidKey}
	}

	for event := range h.ciliumIdentities.Events(ctx) {
		cid := event.Object

		switch event.Kind {
		case resource.Upsert:
			log.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Upsert Cilium Identity event")

			if h.cidTracker.isTracked(cid.Name) {
				cidHandlerFunc(cid, kvstore.EventTypeModify)
			} else {
				h.cidTracker.add(cid.Name)
				cidHandlerFunc(cid, kvstore.EventTypeCreate)
			}
		case resource.Delete:
			log.WithFields(logrus.Fields{
				logfields.CEPName: event.Key.String()}).Debug("Got Delete Cilium Identity event")

			h.cidTracker.remove(cid.Name)
			cidHandlerFunc(cid, kvstore.EventTypeDelete)
		}
		event.Done(nil)
	}
	return nil
}

// WaitForInitialGlobalIdentities waits for the initial set of global security
// identities to have been received and populated into the allocator cache.
func (h *HybridIDAllocator) WaitForInitialGlobalIdentities(ctx context.Context) error {
	select {
	case <-h.globalIdentityAllocatorInitialized:
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
func (h *HybridIDAllocator) AllocateIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error) {
	defer func() { h.RecordCompletedAllocation(id, allocated, false, notifyOwner) }()

	id, allocated, completed, err := h.AllocateLocalIdentity(ctx, lbls, notifyOwner, oldNID)
	if err != nil || completed {
		return id, allocated, err
	}

	// This doesn't allocate global IDs anymore.
	// The above part is required for IPCache to allocate CIDRs for endpoints.
	// It retries to fetch Cilium Identity from watcher's cache.
	// AllocateIdentity fails if Cilium Identity is not found.
	backoff := 500 * time.Millisecond
	maxRetries := 6
	for retry := 0; id == nil && retry < maxRetries; retry++ {
		id = h.lookupGlobalIDByLabels(lbls)
		time.Sleep(backoff)
		backoff = backoff * 2
	}

	if id == nil {
		return nil, false, fmt.Errorf("failed to assign a global identity for lables: %v", lbls.String())
	}

	return id, true, nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func (h *HybridIDAllocator) Release(ctx context.Context, id *identity.Identity, notifyOwner bool) (released bool, err error) {
	defer func() { h.RecordCompletedRelease(id, released, notifyOwner) }()

	released, completed, err := h.ReleaseLocalIdentity(ctx, id, notifyOwner)
	if completed {
		return released, err
	}

	// This doesn't release global IDs anymore.
	// The above part is required for IPCache to release CIDRs for endpoints.
	return false, nil
}

// ReleaseSlice attempts to release a set of identities. It is a helper
// function that may be useful for cleaning up multiple identities in paths
// where several identities may be allocated and another error means that they
// should all be released.
func (h *HybridIDAllocator) ReleaseSlice(ctx context.Context, owner idcache.IdentityAllocatorOwner, identities []*identity.Identity) error {
	var err error
	for _, id := range identities {
		if id == nil {
			continue
		}
		_, err2 := h.Release(ctx, id, false)
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
func (h *HybridIDAllocator) WatchRemoteIdentities(remoteName string, backend kvstore.BackendOperations, cachedPrefix bool) (*allocator.RemoteCache, error) {
	// This is for cluster-mesh. It doesn't work when operator is managing global
	// security identities. Operators need to be connected to each other then.
	return nil, fmt.Errorf("cannot watch remote identities when kvstore is not used and operator is managing global security identities")
}

// GetIdentityCache returns a cache of all known identities
func (h *HybridIDAllocator) GetIdentityCache() idcache.IdentityCache {
	cache := h.GetLocalIdentityCache()

	if !h.isGlobalIdentityAllocatorInitialized() {
		return cache
	}

	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
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
func (h *HybridIDAllocator) GetIdentities() idcache.IdentitiesModel {
	identities := h.GetLocalIdentities()

	if err := h.WaitForInitialGlobalIdentities(context.TODO()); err != nil {
		log.Warningf("GetIdentities failed because global identity cache is not initialized")
		return identities
	}

	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
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

func (h *HybridIDAllocator) isGlobalIdentityAllocatorInitialized() bool {
	cidStore, err := h.ciliumIdentities.Store(h.ctx)

	select {
	case <-h.globalIdentityAllocatorInitialized:
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
func (h *HybridIDAllocator) LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity {
	secID, completed := h.LookupLocalIdentity(ctx, lbls)
	if completed {
		return secID
	}

	if !h.isGlobalIdentityAllocatorInitialized() {
		return nil
	}

	id := h.lookupGlobalIDByLabels(lbls)
	if id != nil {
		return id
	}

	return nil
}

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache, then the caches for remote kvstores and
// finally fall back to the main kvstore
// May return nil for lookups if the allocator has not yet been synchronized.
func (h *HybridIDAllocator) LookupIdentityByID(ctx context.Context, numID identity.NumericIdentity) *identity.Identity {
	secID, completed := h.LookupLocalIdentityByID(ctx, numID)
	if completed {
		return secID
	}

	if !h.isGlobalIdentityAllocatorInitialized() {
		return nil
	}

	cid := h.getCIDByKey(numID.String())
	if cid != nil {
		lblArray := labels.Map2Labels(cid.SecurityLabels, "").LabelArray()
		return identity.NewIdentityFromLabelArray(numID, lblArray)
	}

	return nil
}

func (h *HybridIDAllocator) Close() {
	h.setupMutex.Lock()
	defer h.setupMutex.Unlock()

	close(h.stopChan)
	h.wp.Close()
}

func (h *HybridIDAllocator) lookupGlobalIDByLabels(lbls labels.Labels) *identity.Identity {
	lblArray := lbls.LabelArray()

	cid := h.getCIDByIndex(k8s.ByKeyIndex, lblArray)
	if cid != nil {
		id, err := strconv.Atoi(cid.Name)
		if err != nil {
			log.Errorf("LookupIdentity failed cannot convert ID %q", cid.Name)
			return nil
		}
		return identity.NewIdentityFromLabelArray(identity.NumericIdentity(id), lblArray)
	}

	return nil
}

func (h *HybridIDAllocator) RemoveRemoteIdentities(name string) {
	// HybridIDAllocator doesn't handle remote identities.
	return
}

func (h *HybridIDAllocator) getCIDByIndex(indexName string, lblArray labels.LabelArray) *v2.CiliumIdentity {
	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
	if cidStore == nil {
		return nil
	}

	k := key.GlobalIdentity{LabelArray: lblArray}

	cidList, err := cidStore.ByIndex(indexName, k.GetKey())
	if err != nil {
		return nil
	}
	if len(cidList) < 1 {
		return nil
	}

	var selectedID *v2.CiliumIdentity
	var selectedVal int
	for _, cid := range cidList {
		if selectedID == nil {
			selectedVal, err = strconv.Atoi(cid.Name)
			if err == nil {
				selectedID = cid
			}
			continue
		}

		cidVal, err := strconv.Atoi(cid.Name)
		if err != nil {
			continue
		}

		// Select the smallest value. This is useful in case when there are
		// duplicate identities. This will help with deduplicating identities.
		if cidVal < selectedVal {
			selectedID = cid
			selectedVal = cidVal
		}
	}

	return selectedID
}

func (h *HybridIDAllocator) getCIDByKey(cidName string) *v2.CiliumIdentity {
	cidStore, _ := h.ciliumIdentities.Store(h.ctx)
	if cidStore == nil {
		return nil
	}
	cid, exists, err := cidStore.GetByKey(resource.Key{Name: cidName})
	if err != nil {
		log.Debugf("LookupIdentity failed to GetByKey (%v) from CIDStore: %v", cidName, err)
		return nil
	}
	if !exists {
		log.Debugf("LookupIdentity failed to GetByKey (%v) from CIDStore - doesn't exist", cidName)
		return nil
	}

	return cid
}

func (h *HybridIDAllocator) WithholdLocalIdentities(nids []identity.NumericIdentity) {
	h.WithholdLocalIDs(nids)
}

func (h *HybridIDAllocator) UnwithholdLocalIdentities(nids []identity.NumericIdentity) {
	h.UnwithholdLocalIDs(nids)
}

// Observe the identity changes. Conforms to stream.Observable.
// Replays the current state of the cache when subscribing.
func (h *HybridIDAllocator) Observe(ctx context.Context, next func(idcache.IdentityChange), complete func(error)) {
	// This short-lived go routine serves the purpose of waiting for the global identity allocator becoming ready
	// before starting to observe the underlying allocator for changes.
	// m.IdentityAllocator is backed by a stream.FuncObservable, that will start its own
	// go routine. Therefore, the current go routine will stop and free the lock on the setupMutex after the registration.
	go func() {
		if err := h.WaitForInitialGlobalIdentities(ctx); err != nil {
			complete(ctx.Err())
			return
		}

		h.setupMutex.Lock()
		defer h.setupMutex.Unlock()

		if h.idObserver == nil {
			complete(errors.New("allocator no longer initialized"))
			return
		}

		// Observe the underlying allocator for changes and map the events to identities.
		stream.Map[allocator.AllocatorChange, idcache.IdentityChange](
			h.idObserver, //l.IdentityAllocator,
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
