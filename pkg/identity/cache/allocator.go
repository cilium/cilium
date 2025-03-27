// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cache

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"

	"github.com/cilium/stream"
	"github.com/google/renameio/v2"
	jsoniter "github.com/json-iterator/go"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/kvstore/allocator/doublewrite"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var (
	// IdentitiesPath is the path to where identities are stored in the
	// key-value store.
	IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")
)

// The filename for the local allocator checkpoont. This is periodically
// written, and restored on restart.
// The full path is, by default, /run/cilium/state/local_allocator_state.json
const CheckpointFile = "local_allocator_state.json"

// CachingIdentityAllocator manages the allocation of identities for both
// global and local identities.
type CachingIdentityAllocator struct {
	logger *slog.Logger
	// IdentityAllocator is an allocator for security identities from the
	// kvstore.
	IdentityAllocator *allocator.Allocator

	// globalIdentityAllocatorInitialized is closed whenever the global identity
	// allocator is initialized.
	globalIdentityAllocatorInitialized chan struct{}

	localIdentities *localIdentityCache

	localNodeIdentities *localIdentityCache

	identitiesPath string

	// This field exists is to hand out references that are either for sending
	// and receiving. It should not be used directly without converting it first
	// to a AllocatorEventSendChan or AllocatorEventRecvChan.
	events  allocator.AllocatorEventChan
	watcher identityWatcher

	// setupMutex synchronizes InitIdentityAllocator() and Close()
	setupMutex lock.Mutex

	owner IdentityAllocatorOwner

	checkpointTrigger *trigger.Trigger
	triggerDone       <-chan struct{}

	// restoredIdentities are the set of identities read in from a
	// checkpoint on startup. These should be released, see `restoreLocalIdentities()`
	// for more info.
	restoredIdentities map[identity.NumericIdentity]*identity.Identity

	// checkpointPath is the file where local allocator state should be checkpoointed.
	// The default is /run/cilium/state/local_allocator_state.json, changed only for testing.
	checkpointPath string

	// operatorIDManagement indicates if cilium-operator is managing Cilium Identities.
	operatorIDManagement bool

	// maxAllocAttempts is the number of attempted allocation requests
	// performed before failing. This is mainly introduced for testing purposes.
	maxAllocAttempts int
}

type AllocatorConfig struct {
	EnableOperatorManageCIDs bool
	maxAllocAttempts         int
}

// IdentityAllocatorOwner is the interface the owner of an identity allocator
// must implement
type IdentityAllocatorOwner interface {
	// UpdateIdentities will be called when identities have changed
	//
	// The caller is responsible for making sure the same identity
	// is not present in both 'added' and 'deleted', so that they
	// can be processed in either order.
	UpdateIdentities(added, deleted identity.IdentityMap)

	// GetSuffix must return the node specific suffix to use
	GetNodeSuffix() string
}

// IdentityAllocator is any type which is responsible for allocating security
// identities based of sets of labels, and caching information about identities
// locally.
type IdentityAllocator interface {
	// Identity changes are observable.
	stream.Observable[IdentityChange]

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

	// LookupIdentityByID returns the identity that corresponds to the given
	// labels.
	LookupIdentity(ctx context.Context, lbls labels.Labels) *identity.Identity

	// LookupIdentityByID returns the identity that corresponds to the given
	// numeric identity.
	LookupIdentityByID(ctx context.Context, id identity.NumericIdentity) *identity.Identity

	// GetIdentityCache returns the current cache of identities that the
	// allocator has allocated. The caller should not modify the resulting
	// identities by pointer.
	GetIdentityCache() identity.IdentityMap

	// GetIdentities returns a copy of the current cache of identities.
	GetIdentities() IdentitiesModel

	// WithholdLocalIdentities holds a set of numeric identities out of the local
	// allocation pool(s). Once withheld, a numeric identity can only be used
	// when explicitly requested via AllocateIdentity(..., oldNID).
	WithholdLocalIdentities(nids []identity.NumericIdentity)

	// UnwithholdLocalIdentities removes numeric identities from the withheld set,
	// freeing them for general allocation.
	UnwithholdLocalIdentities(nids []identity.NumericIdentity)
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
		logging.Fatal(m.logger, "InitIdentityAllocator() in succession without calling Close()")
	}

	m.logger.Info("Initializing identity allocator")

	minID := idpool.ID(identity.GetMinimalAllocationIdentity(option.Config.ClusterID))
	maxID := idpool.ID(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))

	m.logger.Info(
		"Allocating identities between range",
		logfields.Min, minID,
		logfields.Max, maxID,
		logfields.ClusterID, option.Config.ClusterID,
	)

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
			m.logger.Debug("Identity allocation backed by KVStore")
			backend, err = kvstoreallocator.NewKVStoreBackend(
				m.logger,
				kvstoreallocator.KVStoreBackendConfiguration{
					BasePath: m.identitiesPath,
					Suffix:   owner.GetNodeSuffix(),
					Typ:      &key.GlobalIdentity{},
					Backend:  kvstore.Client(),
				})
			if err != nil {
				logging.Fatal(m.logger, "Unable to initialize kvstore backend for identity allocation", logfields.Error, err)
			}

		case option.IdentityAllocationModeCRD:
			m.logger.Debug("Identity allocation backed by CRD")
			backend, err = identitybackend.NewCRDBackend(m.logger, identitybackend.CRDBackendConfiguration{
				Store:    nil,
				StoreSet: &atomic.Bool{},
				Client:   client,
				KeyFunc:  (&key.GlobalIdentity{}).PutKeyFromMap,
			})
			if err != nil {
				logging.Fatal(m.logger, "Unable to initialize Kubernetes CRD backend for identity allocation", logfields.Error, err)
			}

		case option.IdentityAllocationModeDoubleWriteReadKVstore, option.IdentityAllocationModeDoubleWriteReadCRD:
			readFromKVStore := true
			if option.Config.IdentityAllocationMode == option.IdentityAllocationModeDoubleWriteReadCRD {
				readFromKVStore = false
			}
			m.logger.Debug("Double-Write Identity allocation mode (CRD and KVStore) with reads from KVStore", logfields.ReadFromKVStore, readFromKVStore)
			backend, err = doublewrite.NewDoubleWriteBackend(
				m.logger,
				doublewrite.DoubleWriteBackendConfiguration{
					CRDBackendConfiguration: identitybackend.CRDBackendConfiguration{
						Store:    nil,
						StoreSet: &atomic.Bool{},
						Client:   client,
						KeyFunc:  (&key.GlobalIdentity{}).PutKeyFromMap,
					},
					KVStoreBackendConfiguration: kvstoreallocator.KVStoreBackendConfiguration{
						BasePath: m.identitiesPath,
						Suffix:   owner.GetNodeSuffix(),
						Typ:      &key.GlobalIdentity{},
						Backend:  kvstore.Client(),
					},
					ReadFromKVStore: readFromKVStore,
				})
			if err != nil {
				logging.Fatal(m.logger, "Unable to initialize the Double Write backend for identity allocation", logfields.Error, err)
			}
		default:
			logging.Fatal(m.logger, fmt.Sprintf("Unsupported identity allocation mode %s", option.Config.IdentityAllocationMode))
		}

		allocOptions := []allocator.AllocatorOption{
			allocator.WithMax(maxID), allocator.WithMin(minID),
			allocator.WithEvents(events),
			allocator.WithPrefixMask(idpool.ID(option.Config.ClusterID << identity.GetClusterIDShift())),
		}
		if m.operatorIDManagement {
			allocOptions = append(allocOptions, allocator.WithOperatorIDManagement())
		} else {
			allocOptions = append(allocOptions, allocator.WithMasterKeyProtection())
		}
		if m.maxAllocAttempts > 0 {
			allocOptions = append(allocOptions, allocator.WithMaxAllocAttempts(m.maxAllocAttempts))
		}
		a, err := allocator.NewAllocator(m.logger, &key.GlobalIdentity{}, backend, allocOptions...)
		if err != nil {
			logging.Fatal(m.logger, fmt.Sprintf("Unable to initialize IdentityAllocator with backend %s", option.Config.IdentityAllocationMode), logfields.Error, err)
		}

		m.IdentityAllocator = a
		close(m.globalIdentityAllocatorInitialized)
	}(m.owner, m.events, minID, maxID)

	return m.globalIdentityAllocatorInitialized
}

// EnableCheckpointing enables checkpointing the local allocator state.
// The CachingIdentityAllocator is used in multiple places, but we only want to
// checkpoint the "primary" allocator
func (m *CachingIdentityAllocator) EnableCheckpointing() {
	controllerManager := controller.NewManager()
	controllerGroup := controller.NewGroup("identity-allocator")
	controllerName := "local-identity-checkpoint"
	triggerDone := make(chan struct{})
	t, _ := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 10 * time.Second,
		TriggerFunc: func(reasons []string) {
			controllerManager.UpdateController(controllerName, controller.ControllerParams{
				Group:    controllerGroup,
				DoFunc:   m.checkpoint,
				StopFunc: m.checkpoint, // perform one last checkpoint when the controller is removed
			})
		},
		ShutdownFunc: func() {
			controllerManager.RemoveControllerAndWait(controllerName) // waits for StopFunc
			close(triggerDone)
		},
	})

	m.checkpointTrigger = t
	m.triggerDone = triggerDone
}

const eventsQueueSize = 1024

// InitIdentityAllocator creates the identity allocator. Only the first
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
func NewCachingIdentityAllocator(logger *slog.Logger, owner IdentityAllocatorOwner, config AllocatorConfig) *CachingIdentityAllocator {
	watcher := identityWatcher{
		owner: owner,
	}

	m := &CachingIdentityAllocator{
		logger:                             logger,
		globalIdentityAllocatorInitialized: make(chan struct{}),
		owner:                              owner,
		identitiesPath:                     IdentitiesPath,
		watcher:                            watcher,
		events:                             make(allocator.AllocatorEventChan, eventsQueueSize),
		operatorIDManagement:               config.EnableOperatorManageCIDs,
		maxAllocAttempts:                   config.maxAllocAttempts,
	}
	if option.Config.RunDir != "" { // disable checkpointing if this is a unit test
		m.checkpointPath = filepath.Join(option.Config.StateDir, CheckpointFile)
	}
	m.watcher.watch(m.events)

	// Local identity cache can be created synchronously since it doesn't
	// rely upon any external resources (e.g., external kvstore).
	m.localIdentities = newLocalIdentityCache(logger, identity.IdentityScopeLocal, identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity)
	m.localNodeIdentities = newLocalIdentityCache(logger, identity.IdentityScopeRemoteNode, identity.MinAllocatorLocalIdentity, identity.MaxAllocatorLocalIdentity)

	return m
}

// Close closes the identity allocator
func (m *CachingIdentityAllocator) Close() {
	m.setupMutex.Lock()
	defer m.setupMutex.Unlock()

	if m.checkpointTrigger != nil {
		m.checkpointTrigger.Shutdown()
		<-m.triggerDone
		m.checkpointTrigger = nil
	}

	select {
	case <-m.globalIdentityAllocatorInitialized:
		// This means the channel was closed and therefore the IdentityAllocator == nil will never be true
	default:
		if m.IdentityAllocator == nil {
			m.logger.Error("Close() called without calling InitIdentityAllocator() first")
			return
		}
	}

	m.IdentityAllocator.Delete()
	if m.events != nil {
		close(m.events)
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
		return fmt.Errorf("initial global identity sync was cancelled: %w", ctx.Err())
	}

	return m.IdentityAllocator.WaitForInitialSync(ctx)
}

var ErrNonLocalIdentity = fmt.Errorf("labels would result in global identity")

// AllocateLocalIdentity works the same as AllocateIdentity, but it guarantees that the allocated
// identity will be local-only. If the provided set of labels does not map to a local identity scope,
// this will return an error.
func (m *CachingIdentityAllocator) AllocateLocalIdentity(lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error) {

	// If this is a reserved, pre-allocated identity, just return that and be done
	if reservedIdentity := identity.LookupReservedIdentityByLabels(lbls); reservedIdentity != nil {
		m.logger.Debug(
			"Resolving reserved identity",
			logfields.Identity, reservedIdentity.ID,
			logfields.IdentityLabels, lbls,
			logfields.New, false,
		)
		return reservedIdentity, false, nil
	}

	m.logger.Debug(
		"Resolving local identity",
		logfields.IdentityLabels, lbls,
	)

	// Allocate according to scope
	var metricLabel string
	switch scope := identity.ScopeForLabels(lbls); scope {
	case identity.IdentityScopeLocal:
		id, allocated, err = m.localIdentities.lookupOrCreate(lbls, oldNID)
		metricLabel = identity.NodeLocalIdentityType
	case identity.IdentityScopeRemoteNode:
		id, allocated, err = m.localNodeIdentities.lookupOrCreate(lbls, oldNID)
		metricLabel = identity.RemoteNodeIdentityType
	default:
		m.logger.Error(
			"BUG: attempt to allocate local identity for labels, but a global identity is required",
			logfields.Labels, lbls,
			logfields.Scope, scope,
		)
		return nil, false, ErrNonLocalIdentity
	}
	if err != nil {
		return nil, false, err
	}

	if allocated {
		metrics.Identity.WithLabelValues(metricLabel).Inc()
		for labelSource := range lbls.CollectSources() {
			metrics.IdentityLabelSources.WithLabelValues(labelSource).Inc()
		}

		if m.checkpointTrigger != nil {
			m.checkpointTrigger.Trigger()
		}

		if notifyOwner {
			added := identity.IdentityMap{
				id.ID: id.LabelArray,
			}
			m.owner.UpdateIdentities(added, nil)
		}
	}

	return
}

// needsGlobalIdentity returns true if these labels require
// allocating a global identity
func needsGlobalIdentity(lbls labels.Labels) bool {
	// If lbls corresponds to a reserved identity, no global allocation required
	if identity.LookupReservedIdentityByLabels(lbls) != nil {
		return false
	}

	// determine identity scope from labels,
	return identity.ScopeForLabels(lbls) == identity.IdentityScopeGlobal
}

// AllocateIdentity allocates an identity described by the specified labels. If
// an identity for the specified set of labels already exist, the identity is
// re-used and reference counting is performed, otherwise a new identity is
// allocated via the kvstore or via the local identity allocator.
// A possible previously used numeric identity for these labels can be passed
// in as the 'oldNID' parameter; identity.InvalidIdentity must be passed if no
// previous numeric identity exists.
func (m *CachingIdentityAllocator) AllocateIdentity(ctx context.Context, lbls labels.Labels, notifyOwner bool, oldNID identity.NumericIdentity) (id *identity.Identity, allocated bool, err error) {
	if !needsGlobalIdentity(lbls) {
		return m.AllocateLocalIdentity(lbls, notifyOwner, oldNID)
	}

	if option.Config.Debug {
		m.logger.Debug(
			"Resolving global identity",
			logfields.IdentityLabels, lbls,
		)
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

	idp, allocated, isNewLocally, err := m.IdentityAllocator.Allocate(ctx, &key.GlobalIdentity{LabelArray: lbls.LabelArray()})
	if err != nil {
		return nil, false, err
	}
	if idp > identity.MaxNumericIdentity {
		return nil, false, fmt.Errorf("%d: numeric identity too large", idp)
	}
	id = identity.NewIdentity(identity.NumericIdentity(idp), lbls)

	if option.Config.Debug {
		m.logger.Debug(
			"Resolved identity",
			logfields.Identity, idp,
			logfields.IdentityLabels, lbls,
			logfields.New, allocated,
			logfields.NewLocally, isNewLocally,
		)
	}

	if allocated || isNewLocally {
		metrics.Identity.WithLabelValues(identity.ClusterLocalIdentityType).Inc()
		for labelSource := range lbls.CollectSources() {
			metrics.IdentityLabelSources.WithLabelValues(labelSource).Inc()
		}
	}

	// Notify the owner of the newly added identities so that the
	// cached identities can be updated ASAP, rather than just
	// relying on the kv-store update events.
	if allocated && notifyOwner {
		added := identity.IdentityMap{
			id.ID: id.LabelArray,
		}
		m.owner.UpdateIdentities(added, nil)
	}

	return id, allocated, nil
}

func (m *CachingIdentityAllocator) WithholdLocalIdentities(nids []identity.NumericIdentity) {
	m.logger.Debug(
		"Withholding numeric identities for later restoration",
		logfields.Identity, nids,
	)

	// The allocators will return any identities that are not in-scope.
	nids = m.localIdentities.withhold(nids)
	nids = m.localNodeIdentities.withhold(nids)
	if len(nids) > 0 {
		m.logger.Error(
			"Attempt to restore invalid numeric identities.",
			logfields.Identity, nids,
		)
	}
}

func (m *CachingIdentityAllocator) UnwithholdLocalIdentities(nids []identity.NumericIdentity) {
	m.logger.Debug(
		"Unwithholding numeric identities",
		logfields.Identity, nids,
	)

	// The allocators will ignore any identities that are not in-scope.
	m.localIdentities.unwithhold(nids)
	m.localNodeIdentities.unwithhold(nids)
}

// checkpoint writes the state of the local allocators to disk. This is used for restoration,
// to ensure that numeric identities are, as much as possible, stable across agent restarts.
//
// Do not call this directly, rather, use m.checkpointTrigger.Trigger()
func (m *CachingIdentityAllocator) checkpoint(ctx context.Context) error {
	if m.checkpointPath == "" {
		return nil // this is a unit test
	}
	scopedLog := m.logger.With(logfields.Path, m.checkpointPath)

	ids := make([]*identity.Identity, 0, m.localIdentities.size()+m.localNodeIdentities.size())
	ids = m.localIdentities.checkpoint(ids)
	ids = m.localNodeIdentities.checkpoint(ids)

	// use renameio to prevent partial writes
	out, err := renameio.NewPendingFile(m.checkpointPath, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
	if err != nil {
		scopedLog.Error("failed to prepare checkpoint file", logfields.Error, err)
		return err
	}
	defer out.Cleanup()

	jw := jsoniter.ConfigFastest.NewEncoder(out)
	if err := jw.Encode(ids); err != nil {
		scopedLog.Error("failed to marshal identity checkpoint state", logfields.Error, err)
		return err
	}
	if err := out.CloseAtomicallyReplace(); err != nil {
		scopedLog.Error("failed to write identity checkpoint file", logfields.Error, err)
		return err
	}
	scopedLog.Debug("Wrote local identity allocator checkpoint")
	return nil
}

// RestoreLocalIdentities reads in the checkpointed local allocator state
// from disk and allocates a reference to every previously existing identity.
//
// Once all identity-allocating objects are synchronized (e.g. network policies,
// remote nodes), call ReleaseRestoredIdentities to release the held references.
func (m *CachingIdentityAllocator) RestoreLocalIdentities() (map[identity.NumericIdentity]*identity.Identity, error) {
	if m.checkpointPath == "" {
		return nil, nil // unit test
	}
	scopedLog := m.logger.With(logfields.Path, m.checkpointPath)

	// Read in checkpoint file
	fp, err := os.Open(m.checkpointPath)
	if err != nil {
		if os.IsNotExist(err) {
			scopedLog.Info("No identity checkpoint file found, skipping restoration")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open identity checkpoint file %s: %w", m.checkpointPath, err)
	}
	defer fp.Close()

	jr := jsoniter.ConfigFastest.NewDecoder(fp)
	var ids []*identity.Identity
	if err := jr.Decode(&ids); err != nil {
		return nil, fmt.Errorf("failed to parse identity checkpoint file %s: %w", m.checkpointPath, err)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Load in checkpoint:
	// - withhold numeric identities
	// - allocate previous identities
	// - update SelectorCache
	// - unwithhold numeric IDs

	scopedLog.Info("Restoring checkpointed local identities", logfields.Count, len(ids))
	m.restoredIdentities = make(map[identity.NumericIdentity]*identity.Identity, len(ids))
	added := make(identity.IdentityMap, len(ids))

	// Withhold restored local identities from allocation (except by request).
	// This is insurance against a code change causing identities to be allocated
	// differently, which could disrupt restoration.
	// Withholding numeric IDs prevents them from being allocated except by explicit request.
	oldNumIDs := make([]identity.NumericIdentity, 0, len(ids))
	for _, id := range ids {
		oldNumIDs = append(oldNumIDs, id.ID)
	}
	m.WithholdLocalIdentities(oldNumIDs)

	for _, oldID := range ids {
		// Ensure we do not restore any global identities or identities that somehow are
		// changing scope. There's no point, as the numeric identity will be different.
		if scope := identity.ScopeForLabels(oldID.Labels); scope != oldID.ID.Scope() || needsGlobalIdentity(oldID.Labels) {
			// Should not happen, except when the scope for labels changes
			// such as disabling policy-cidr-match-mode=nodes
			scopedLog.Warn(
				"skipping restore of non-local or re-scoped identity",
				logfields.Identity, oldID,
				logfields.Scope, scope,
			)
			continue
		}

		newID, _, err := m.AllocateLocalIdentity(
			oldID.Labels,
			false,    // do not add to selector cache; we'll batch that later
			oldID.ID, // request previous numeric ID
		)
		if err != nil {
			scopedLog.Error(
				"failed to restore checkpointed local identity, continuing",
				logfields.Identity, oldID,
				logfields.Error, err,
			)
		} else {
			m.restoredIdentities[newID.ID] = newID
			added[newID.ID] = newID.LabelArray
			if newID.ID != oldID.ID {
				// Paranoia, shouldn't happen
				scopedLog.Warn(
					"Restored local identity has different numeric ID",
					logfields.Identity, oldID,
				)
			}
		}
	}

	// Add identities to SelectorCache
	if m.owner != nil {
		m.owner.UpdateIdentities(added, nil)
	}

	// Release all withheld numeric identities back for general use.
	m.UnwithholdLocalIdentities(oldNumIDs)

	// return the set of restored identities, which is useful for prefix restoration
	return m.restoredIdentities, nil
}

// ReleaseRestoredIdentities releases any identities that were restored, reducing their reference
// count and cleaning up as necessary.
func (m *CachingIdentityAllocator) ReleaseRestoredIdentities() {
	deleted := make(identity.IdentityMap, len(m.restoredIdentities))
	for _, id := range m.restoredIdentities {
		released, err := m.Release(context.Background(), id, false)
		if err != nil {
			// This should never happen; these IDs are local
			m.logger.Error(
				"failed to release restored identity",
				logfields.Identity, id,
				logfields.Error, err,
			)
			continue
		}
		if option.Config.Debug {
			m.logger.Debug(
				"Released restored identity reference",
				logfields.Identity, id,
				logfields.Released, released,
			)
		}
		if released {
			deleted[id.ID] = id.LabelArray
		}
	}

	if len(deleted) > 0 && m.owner != nil {
		m.owner.UpdateIdentities(nil, deleted)
	}

	m.restoredIdentities = nil // free memory
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
// After the last user has released the ID, the returned lastUse value is true.
func (m *CachingIdentityAllocator) Release(ctx context.Context, id *identity.Identity, notifyOwner bool) (released bool, err error) {
	metricVal := identity.ClusterLocalIdentityType
	defer func() {
		if released {
			// decrement metrics, trigger checkpoint if local
			if metricVal != identity.ClusterLocalIdentityType && m.checkpointTrigger != nil {
				m.checkpointTrigger.Trigger()
			}
			for labelSource := range id.Labels.CollectSources() {
				metrics.IdentityLabelSources.WithLabelValues(labelSource).Dec()
			}
			metrics.Identity.WithLabelValues(metricVal).Dec()
		}

		// Remove this ID from the selectorcache and any other identity "watchers"
		if m.owner != nil && released && notifyOwner {
			deleted := identity.IdentityMap{
				id.ID: id.LabelArray,
			}
			m.owner.UpdateIdentities(nil, deleted)
		}
	}()

	// Ignore reserved identities.
	if id.IsReserved() {
		return false, nil
	}

	// Release local identities
	// will perform post-release cleanup actions above
	switch identity.ScopeForLabels(id.Labels) {
	case identity.IdentityScopeLocal:
		metricVal = identity.NodeLocalIdentityType
		return m.localIdentities.release(id), nil
	case identity.IdentityScopeRemoteNode:
		metricVal = identity.RemoteNodeIdentityType
		return m.localNodeIdentities.release(id), nil
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

// WatchRemoteIdentities returns a RemoteCache instance which can be later
// started to watch identities in another kvstore and sync them to the local
// identity cache. remoteName should be unique unless replacing an existing
// remote's backend. When cachedPrefix is set, identities are assumed to be
// stored under the "cilium/cache" prefix, and the watcher is adapted accordingly.
func (m *CachingIdentityAllocator) WatchRemoteIdentities(remoteName string, remoteID uint32, backend kvstore.BackendOperations, cachedPrefix bool) (allocator.RemoteIDCache, error) {
	<-m.globalIdentityAllocatorInitialized

	prefix := m.identitiesPath
	if cachedPrefix {
		prefix = path.Join(kvstore.StateToCachePrefix(prefix), remoteName)
	}

	remoteAllocatorBackend, err := kvstoreallocator.NewKVStoreBackend(m.logger, kvstoreallocator.KVStoreBackendConfiguration{BasePath: prefix, Suffix: m.owner.GetNodeSuffix(), Typ: &key.GlobalIdentity{}, Backend: backend})
	if err != nil {
		return nil, fmt.Errorf("error setting up remote allocator backend: %w", err)
	}

	remoteAlloc, err := allocator.NewAllocator(m.logger,
		&key.GlobalIdentity{}, remoteAllocatorBackend,
		allocator.WithEvents(m.IdentityAllocator.GetEvents()), allocator.WithoutGC(), allocator.WithoutAutostart(),
		allocator.WithCacheValidator(clusterIDValidator(remoteID)),
		allocator.WithCacheValidator(clusterNameValidator(remoteName)),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize remote Identity Allocator: %w", err)
	}

	return m.IdentityAllocator.NewRemoteCache(remoteName, remoteAlloc), nil
}

func (m *CachingIdentityAllocator) RemoveRemoteIdentities(name string) {
	if m.IdentityAllocator != nil {
		m.IdentityAllocator.RemoveRemoteKVStore(name)
	}
}

type IdentityChangeKind string

const (
	IdentityChangeSync   IdentityChangeKind = IdentityChangeKind(allocator.AllocatorChangeSync)
	IdentityChangeUpsert IdentityChangeKind = IdentityChangeKind(allocator.AllocatorChangeUpsert)
	IdentityChangeDelete IdentityChangeKind = IdentityChangeKind(allocator.AllocatorChangeDelete)
)

type IdentityChange struct {
	Kind   IdentityChangeKind
	ID     identity.NumericIdentity
	Labels labels.Labels
}

// Observe identity changes. Doesn't include local identities. Conforms to stream.Observable.
// Replays the current state of the cache when subscribing.
func (m *CachingIdentityAllocator) Observe(ctx context.Context, next func(IdentityChange), complete func(error)) {
	// This short-lived go routine serves the purpose of waiting for the global identity allocator becoming ready
	// before starting to observe the underlying allocator for changes.
	// m.IdentityAllocator is backed by a stream.FuncObservable, that will start its own
	// go routine. Therefore, the current go routine will stop and free the lock on the setupMutex after the registration.
	go func() {
		if err := m.WaitForInitialGlobalIdentities(ctx); err != nil {
			complete(ctx.Err())
			return
		}

		m.setupMutex.Lock()
		defer m.setupMutex.Unlock()

		if m.IdentityAllocator == nil {
			complete(errors.New("allocator no longer initialized"))
			return
		}

		// Observe the underlying allocator for changes and map the events to identities.
		stream.Map[allocator.AllocatorChange, IdentityChange](
			m.IdentityAllocator,
			func(change allocator.AllocatorChange) IdentityChange {
				return IdentityChange{
					Kind:   IdentityChangeKind(change.Kind),
					ID:     identity.NumericIdentity(change.ID),
					Labels: mapLabels(change.Key),
				}
			},
		).Observe(ctx, next, complete)
	}()
}

func mapLabels(allocatorKey allocator.AllocatorKey) labels.Labels {
	var idLabels labels.Labels = nil

	if allocatorKey != nil {
		idLabels = labels.Labels{}
		for k, v := range allocatorKey.GetAsMap() {
			label := labels.ParseLabel(k + "=" + v)
			idLabels[label.Key] = label
		}
	}

	return idLabels
}

// LocalIdentityChanges returns an observable for (only) node-local identities.
// Replays current state on subscription followed by a Sync event.
func (m *CachingIdentityAllocator) LocalIdentityChanges() stream.Observable[IdentityChange] {
	return m.localIdentities
}

// clusterIDValidator returns a validator ensuring that the identity ID belongs
// to the ClusterID range.
func clusterIDValidator(clusterID uint32) allocator.CacheValidator {
	min := idpool.ID(identity.GetMinimalAllocationIdentity(clusterID))
	max := idpool.ID(identity.GetMaximumAllocationIdentity(clusterID))

	return func(_ allocator.AllocatorChangeKind, id idpool.ID, _ allocator.AllocatorKey) error {
		if id < min || id > max {
			return fmt.Errorf("ID %d does not belong to the allocation range of cluster ID %d", id, clusterID)
		}
		return nil
	}
}

// clusterNameValidator returns a validator ensuring that the identity labels
// include the one specifying the correct cluster name.
func clusterNameValidator(clusterName string) allocator.CacheValidator {
	return func(kind allocator.AllocatorChangeKind, _ idpool.ID, ak allocator.AllocatorKey) error {
		if kind != allocator.AllocatorChangeUpsert {
			// Don't filter out deletion events, as labels may not be propagated,
			// and to prevent leaving stale identities behind.
			return nil
		}

		gi, ok := ak.(*key.GlobalIdentity)
		if !ok {
			return fmt.Errorf("unsupported key type %T", ak)
		}

		var found bool
		for _, lbl := range gi.LabelArray {
			if lbl.Key != api.PolicyLabelCluster {
				continue
			}

			switch {
			case lbl.Source != labels.LabelSourceK8s:
				return fmt.Errorf("unexpected source for cluster label: got %s, expected %s", lbl.Source, labels.LabelSourceK8s)
			case lbl.Value != clusterName:
				return fmt.Errorf("unexpected cluster name: got %s, expected %s", lbl.Value, clusterName)
			default:
				found = true
			}
		}

		if !found {
			return fmt.Errorf("could not find expected label %s", api.PolicyLabelCluster)
		}

		return nil
	}
}
