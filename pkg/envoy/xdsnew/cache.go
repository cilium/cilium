// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	controlplanelog "github.com/envoyproxy/go-control-plane/pkg/log"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/revert"
)

const (
	logFieldComponent = "component"
)

type Cache interface {
	// GetSnapshotCache returns SnapshotCache to be passed to go-control-plane.
	GetSnapshotCache() cache.SnapshotCache

	// ApplyResources commits non-revertible semantic changes. Envoy NACKs report
	// rejection to caller waits without reverting these resources. Semantically
	// equal upserts also become non-revertible, without changing their revisions.
	// Completions for unchanged resource types attach to their current version
	// instead of creating a completion-only generation.
	// waitTypeURLs explicitly selects the resource types to wait for. An empty
	// set selects no waits. Selected types with no names in mutations are ignored.
	//
	// A wait whose pending requirements for a TypeURL are all removals survives
	// that type's NACKs until a qualifying ACK, cancellation, or timeout. Upserts
	// of other types do not change this policy, but their failures can still fail
	// a shared WaitGroup.
	ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set) error
	// ApplyResourcesWithRollback enables response-owned NACK rollback for changed
	// upserts and returns a non-nil caller rollback covering upserts and removals,
	// with a stateless no-op for semantic no-ops. Errors return nil.
	// Revert restores deleted values only if their names remain absent and no newer
	// API deletion has superseded them, including deletion of an already absent name.
	// Later API reuse of an unchanged value supersedes older caller recovery for
	// that resource, even before ACK. Response-owned recovery remains independent.
	// Each lifecycle must eventually be finalized or reverted; either call is terminal.
	// ACK wait behavior is the same as ApplyResources.
	ApplyResourcesWithRollback(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set) (Rollback, error)
	// ApplyResource compares only the named resource and builds a sparse mutation
	// only after detecting an actual semantic change. It accepts every supported
	// typeURL. A nil resource removes the named resource; typeURL identifies its
	// type even for removals. Committed upserts are non-revertible, including
	// semantically equal upserts. NACKs report rejection to caller waits without
	// reverting these resources or removals.
	// Pending removal waits survive this type's NACKs, with the same wait semantics
	// as ApplyResources.
	ApplyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup) error
	// ApplyResourceWithRollback enables response-owned NACK rollback for a changed
	// upsert and returns a non-nil caller rollback, including for removals.
	// Reuse and removal recovery follow ApplyResourcesWithRollback's
	// supersession rules. Semantic no-ops return a stateless no-op; errors return
	// nil. Each lifecycle must eventually be finalized or reverted; either call is
	// terminal even if Revert returns an error.
	// ACK wait behavior is the same as ApplyResource.
	ApplyResourceWithRollback(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup) (Rollback, error)
	// GetResource returns one cache-owned immutable resource without
	// materializing the complete desired resource maps, or nil if absent.
	GetResource(nodeID string, typeURL typeurl.Index, resourceName string) cache_types.Resource
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
	// HasNode reports whether this consumer was configured at cache construction.
	// An empty desired state remains authoritative across stream reconnects.
	HasNode(nodeID string) bool
}

type Rollback = callbacks.Rollback

// ListenerChange describes one committed listener transition. Previous is nil
// for an insertion and Current is nil for a removal. Resources are immutable
// cache-owned protobufs.
type ListenerChange struct {
	Previous *envoy_config_listener.Listener
	Current  *envoy_config_listener.Listener
}

// ListenerObserver tracks whether committed listener changes leave a node
// without a client that can ACK network policy updates.
type ListenerObserver interface {
	// ApplyCommittedChanges runs under the cache lock after a successful
	// listener mutation. It returns true if NPDS waits should be detached.
	// The implementation must not call back into the cache or take the ADS
	// server mutex.
	ApplyCommittedChanges(nodeID string, changes []ListenerChange) bool

	// HasNPDSListeners runs under the cache lock while registering a policy
	// update. It must return true for nodes the observer does not track, so
	// their explicit ACK waits remain intact. The implementation must not
	// call back into the cache or take the ADS server mutex.
	HasNPDSListeners(nodeID string) bool
}

// CacheOption configures a cache before it can receive resource mutations.
type CacheOption func(*cacheImpl)

// WithNodeIDs initializes persistent desired state for the intended consumers.
// Requests and mutations cannot introduce additional nodes. Empty IDs are not
// valid xDS consumers and are ignored. No snapshots are generated here.
func WithNodeIDs(nodeIDs ...string) CacheOption {
	return func(c *cacheImpl) {
		for _, nodeID := range nodeIDs {
			if nodeID != "" && !c.HasNode(nodeID) {
				c.nodeStates.Insert(&nodeState{nodeID: nodeID})
			}
		}
	}
}

// WithListenerObserver supplies listener-derived NPDS wait decisions to the
// cache. A nil observer leaves standalone cache users' explicit waits intact.
func WithListenerObserver(observer ListenerObserver) CacheOption {
	return func(c *cacheImpl) {
		c.listenerObserver = observer
	}
}

type cacheImpl struct {
	// cacheImpl overrides cache.SnapShotCache by composition and selective interface function
	// overrides to synchronize mutating operations by taking 'mutex'.
	snapshotCache cache.SnapshotCache

	// mutex protects cache state and serializes complete resource mutations.
	// Mutations hold the write lock from semantic comparison through commit and
	// any immediate publication, then release it before responses or completions.
	// When both are needed, this lock precedes go-control-plane's internal
	// locks. Tracked response sends must not wait for a stream consumer while
	// either lock is held.
	mutex *lock.RWMutex
	// nodeStates is immutable after construction, so membership and nodeID reads
	// need no cache lock. The usual single local node is stored inline by Set.
	nodeStates set.Set[*nodeState]
	// Responses are relayed through cache-owned channels so response-owned
	// rollback state is claimed before it can be coalesced with a later update.
	// A response channel can serve watches from several nodes, so relays are
	// channel-owned rather than belonging to any one nodeState.
	watchRelays   map[chan cache.Response]*watchRelay
	logger        *slog.Logger
	completionCbs *callbacks.CompletionCallbacks
	// resourceGeneration is the latest number reserved from the shared mutation
	// sequence. Only nextResourceGenerationLocked advances it, under mutex.
	resourceGeneration callbacks.Generation
	// listenerObserver is supplied by the ADS server. A nil observer leaves
	// standalone cache users' explicit ACK waits unchanged.
	listenerObserver ListenerObserver
}

// SnapshotCache returns SnapshotCache to be passed to go-control-plane.
func (c *cacheImpl) GetSnapshotCache() cache.SnapshotCache {
	return c
}

// nodeWatchState indexes open watches by resource type. Each type can have
// multiple watches because several streams can subscribe to different named
// subsets for the same node. Within one ADS stream, go-control-plane maintains
// one current watch per type containing the requested names; a subsequent
// request replaces that watch rather than adding a watch per resource.
// Index watch pointers, not requests: independent watches may share a request.
type nodeWatchState = typeurl.Map[set.Set[*trackedWatch]]

// watchRelay buffers go-control-plane's synchronous responses until the caller
// can retire served watches and release the cache locks. Sharing a relay per
// stream response channel preserves the order of a publication's responses
// across resource types, without a separate forwarding goroutine.
type watchRelay struct {
	// inner is cache-owned; go-control-plane sends here while holding its locks.
	inner chan cache.Response
	// outer belongs to the stream; forwarding here may block on its consumer.
	outer   chan cache.Response
	watches set.Set[*trackedWatch]
}

type trackedWatch struct {
	state   *nodeState
	typeURL typeurl.Index
	request *cache.Request
	relay   *watchRelay
	cancel  func()
}

// isOpen reports whether the watch is still owned by its relay. Caller must
// hold cacheImpl.mutex.
func (watch *trackedWatch) isOpen() bool {
	return watch != nil && watch.relay != nil && watch.relay.watches.Has(watch)
}

type responseDelivery struct {
	channel   chan cache.Response
	responses []cache.Response
}

var _ Cache = &cacheImpl{}

// snapshotResourceGroup keeps published resources with their aggregate wire
// generation, independently of the entries' revisions and transaction IDs.
type snapshotResourceGroup struct {
	resources  cache.Resources
	generation callbacks.Generation
}

// ciliumSnapshot implements go-control-plane's ResourceSnapshot interface for
// both Envoy core resources and Cilium-specific xDS resources. Resource groups
// are the published copy-on-write state in the same representation used by
// go-control-plane's native Snapshot. Versions use generations and the node
// epoch, leaving resource marshaling to go-control-plane's response path.
type ciliumSnapshot struct {
	resourceGroups typeurl.Slots[snapshotResourceGroup]
	epoch          uint64
}

// Ensure ciliumSnapshot implements cache.ResourceSnapshot.
var _ cache.ResourceSnapshot = &ciliumSnapshot{}

func newCiliumSnapshot(resourceGroups typeurl.Slots[snapshotResourceGroup], epoch uint64) *ciliumSnapshot {
	for typeURL := range typeurl.Count {
		group := resourceGroups[typeURL]
		group.resources.Version = formatXDSVersion(epoch, group.generation)
		resourceGroups[typeURL] = group
	}
	return &ciliumSnapshot{
		resourceGroups: resourceGroups,
		epoch:          epoch,
	}
}

func (w *ciliumSnapshot) GetVersion(typeURLString string) string {
	typeURL, ok := typeurl.FromURL(typeURLString)
	if !ok {
		return ""
	}
	return w.resourceGroups[typeURL].resources.Version
}

func (w *ciliumSnapshot) GetResources(typeURL string) map[string]cache_types.Resource {
	resources := w.GetResourcesAndTTL(typeURL)
	if len(resources) == 0 {
		return nil
	}
	out := make(map[string]cache_types.Resource, len(resources))
	for name, resource := range resources {
		out[name] = resource.Resource
	}
	return out
}

func (w *ciliumSnapshot) GetResourcesAndTTL(typeURLString string) map[string]cache_types.ResourceWithTTL {
	typeURL, ok := typeurl.FromURL(typeURLString)
	if !ok {
		return nil
	}
	return w.resourceGroups[typeURL].resources.Items
}

func (w *ciliumSnapshot) ConstructVersionMap() error {
	if w == nil {
		return fmt.Errorf("missing snapshot")
	}
	return fmt.Errorf("delta xDS is not supported by cilium snapshot")
}

func (w *ciliumSnapshot) GetVersionMap(string) map[string]string {
	return nil
}

func snapshotCacheLogger(logger *slog.Logger) controlplanelog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(logFieldComponent, "go-control-plane-snapshot-cache")

	debugLogger := func(format string, args ...any) {
		// Check before formatting on each call so runtime log-level changes apply.
		if logger.Enabled(context.Background(), slog.LevelDebug) {
			logger.Debug(fmt.Sprintf(format, args...))
		}
	}

	return controlplanelog.LoggerFuncs{
		DebugFunc: debugLogger,
		InfoFunc:  debugLogger, // Punt info to debug to calm the logs
		WarnFunc: func(format string, args ...any) {
			logger.Warn(fmt.Sprintf(format, args...))
		},
		ErrorFunc: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...))
		},
	}
}

func NewCache(logger *slog.Logger, options ...CacheOption) Cache {
	return newCache(logger, options...)
}

func newCache(logger *slog.Logger, options ...CacheOption) *cacheImpl {
	// ADS transport is configured by the server. The snapshot cache's ADS mode
	// would withhold named responses unless they request the complete group,
	// preventing independent subscriptions from consuming their own resources.
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, snapshotCacheLogger(logger))

	c := &cacheImpl{
		snapshotCache: snapshotCache,
		mutex:         &lock.RWMutex{},
		watchRelays:   make(map[chan cache.Response]*watchRelay),
		logger:        logger,
	}
	c.completionCbs = callbacks.NewCompletionCallbacks(logger, c)
	for _, option := range options {
		option(c)
	}
	return c
}
func clusterEndpointName(name string, cluster *envoy_config_cluster.Cluster) string {
	if cluster == nil || cluster.GetType() != envoy_config_cluster.Cluster_EDS {
		return ""
	}
	serviceName := cluster.GetEdsClusterConfig().GetServiceName()
	if serviceName == "" {
		serviceName = cluster.GetName()
	}
	if serviceName == "" {
		serviceName = name
	}
	return serviceName
}

// updateResourceEntries clones only when a published entry changes. Missing
// CLAs are a snapshot projection, never an insertion into desired state.
// The boolean reports map changes using the existing copy-on-write decision.
func (resources *resourceMaps) updateResourceEntries(typeURL typeurl.Index, changed set.Set[string], endpointReferences set.Set[string], previous cache.Resources) (cache.Resources, bool) {
	items := previous.Items
	cloned := false
	for name := range changed.Members() {
		resource := resources[typeURL][name].resource
		old, exists := items[name]
		if resource == nil && endpointReferences.Has(name) {
			// Reuse an unchanged synthetic CLA rather than allocating it again.
			cla, ok := old.Resource.(*envoy_config_endpoint.ClusterLoadAssignment)
			if ok && exists && len(cla.GetEndpoints()) == 0 &&
				xds.ResourceEqual(old.Resource, &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}) {
				continue
			}
			resource = &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
		}
		if resource == nil && !exists || exists && old.Resource == resource {
			continue
		}
		if !cloned {
			items = maps.Clone(items)
			cloned = true
		}
		if resource == nil {
			delete(items, name)
		} else {
			if items == nil {
				items = make(map[string]cache_types.ResourceWithTTL)
			}
			items[name] = cache_types.ResourceWithTTL{Resource: resource}
		}
	}
	if len(items) == 0 {
		items = nil
	}
	return cache.Resources{Items: items}, cloned
}

func (c *cacheImpl) generateSnapshotFromState(state *nodeState) *ciliumSnapshot {
	var resourceGroups typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Count {
		var group cache.Resources
		entries := state.resources[typeURL]
		capacity := len(entries)
		if typeURL == typeurl.Endpoint && len(state.resources[typeurl.Cluster]) > 0 {
			// Size by unique assignment names, not Cluster count: many Clusters
			// can share an EDS service, and non-EDS Clusters need no assignment.
			names := make(map[string]struct{}, len(entries)+len(state.resources[typeurl.Cluster]))
			for name := range entries {
				names[name] = struct{}{}
			}
			for clusterName, entry := range state.resources[typeurl.Cluster] {
				if name := clusterEndpointName(clusterName, typedResource[*envoy_config_cluster.Cluster](entry.resource)); name != "" {
					names[name] = struct{}{}
				}
			}
			capacity = len(names)
		}
		if capacity != 0 {
			group.Items = make(map[string]cache_types.ResourceWithTTL, capacity)
		}
		for name, entry := range entries {
			group.Items[name] = cache_types.ResourceWithTTL{Resource: entry.resource}
		}
		if typeURL == typeurl.Endpoint {
			// EDS also needs empty CLAs for Clusters without desired assignments.
			// Project directly from Clusters, using the destination map to deduplicate
			// shared EDS service names and preserve explicit CLAs. A per-name Cluster
			// scan would make a full snapshot quadratic. Never change desired state.
			for clusterName, entry := range state.resources[typeurl.Cluster] {
				name := clusterEndpointName(clusterName, typedResource[*envoy_config_cluster.Cluster](entry.resource))
				if name == "" {
					continue
				}
				if _, exists := group.Items[name]; exists {
					continue
				}
				resource := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
				group.Items[name] = cache_types.ResourceWithTTL{Resource: resource}
			}
		}
		if len(group.Items) == 0 {
			group.Items = nil
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources:  group,
			generation: state.typeStates[typeURL].generation,
		}
	}
	return newCiliumSnapshot(resourceGroups, state.epoch)
}

func (c *cacheImpl) generateSnapshotFromStateIncrementally(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) *ciliumSnapshot {
	previousSnapshot, ok := previous.(*ciliumSnapshot)
	if !ok || previousSnapshot == nil {
		// Rebuild from desired state when no Cilium baseline exists.
		return c.generateSnapshotFromState(state)
	}
	regenerate := snapshotTypesChangedBy(changedTypeURLs)

	resourceGroups := previousSnapshot.resourceGroups
	for typeURL := range regenerate.Members() {
		previousGroup := previousSnapshot.resourceGroups[typeURL]
		generation := state.typeStates[typeURL].generation
		changed := state.typeStates[typeURL].changedResourceNames
		var endpointReferences set.Set[string]
		var replay bool
		if typeURL == typeurl.Endpoint {
			changed = state.resources.changedEndpointResourceNames(previousSnapshot,
				state.typeStates[typeurl.Cluster].changedResourceNames, state.typeStates[typeurl.Endpoint].changedResourceNames)
			endpointReferences, replay = state.endpointReferencesForSnapshot(previousSnapshot, changed)
		}
		group, resourcesChanged := state.resources.updateResourceEntries(typeURL, changed, endpointReferences, previousGroup.resources)
		if typeURL == typeurl.Endpoint && (replay || resourcesChanged) {
			// CDS mutations can change projected CLAs or require unchanged EDS
			// to be replayed for Cluster warming. Both need a new EDS wire version,
			// without changing desired CLA revisions or transaction IDs.
			generation = max(generation, state.typeStates[typeurl.Cluster].generation)
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources:  group,
			generation: generation,
		}
	}
	return newCiliumSnapshot(resourceGroups, state.epoch)
}

func (c *cacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return c.completionCbs
}

type immediateCompletion struct {
	comp *completion.Completion
	err  error
}

// generationWait describes ACK/NACK requirements and their response boundary.
// Its zero value means no wait; a nonempty scope may have generation zero.
type generationWait struct {
	generation callbacks.Generation
	scope      callbacks.ResourceScope
}

type typeURLWaits = typeurl.Map[generationWait]

// resourceTransaction owns one atomic cache mutation. The cache, context and
// node are fixed when the transaction starts, while response delivery and
// completion work is accumulated for execution after mutex is released.
type resourceTransaction struct {
	cache *cacheImpl
	ctx   context.Context

	// API calls look up state once; lifecycle reverts reuse their persistent
	// node reference. Known nodes keep the same state for the cache's lifetime.
	state *nodeState

	// generation is reserved for this mutation, including corrective reverts.
	// Only API mutations also use it as the changed entries' TransactionID.
	generation            callbacks.Generation
	deliveries            []responseDelivery
	registeredCompletions set.Set[*completion.Completion]
	immediateCompletions  []immediateCompletion
	listenerChanges       []ListenerChange
	updateErr             error
}

// beginResourceTransaction acquires the cache lock for a known node. Pair it
// with complete, which releases the lock before delivering responses or completing waits.
func (c *cacheImpl) beginResourceTransaction(ctx context.Context, state *nodeState) resourceTransaction {
	c.mutex.Lock()
	return resourceTransaction{
		cache: c,
		ctx:   ctx,
		state: state,
	}
}

// nextResourceGenerationLocked is the shared source of mutation generations,
// resource revisions, and API transaction identities. Failed attempts may leave
// gaps in the sequence, but never rewind it. Caller must hold c.mutex.
func (c *cacheImpl) nextResourceGenerationLocked() callbacks.Generation {
	c.resourceGeneration++
	return c.resourceGeneration
}

func (tx *resourceTransaction) complete() {
	c := tx.cache
	var noListenerWaiters callbacks.DetachedWaiters
	if tx.updateErr == nil && len(tx.listenerChanges) > 0 &&
		c.listenerObserver != nil && c.listenerObserver.ApplyCommittedChanges(tx.state.nodeID, tx.listenerChanges) {
		// Detach while holding the cache lock. A new policy update can
		// register a wait after a listener is re-added, even if its
		// resource revision predates this removal.
		noListenerWaiters = c.completionCbs.TakePendingWaiters(tx.state.nodeID, typeurl.NetworkPolicy)
	}
	c.mutex.Unlock()
	c.deliverResponses(tx.deliveries)
	if tx.updateErr != nil {
		// Unchanged-resource waits may have been registered before publication.
		// Detach every transaction-owned wait before waking its caller.
		for comp := range tx.registeredCompletions.Members() {
			c.completionCbs.RemoveTypeGenerationCompletion(comp)
		}
		for comp := range tx.registeredCompletions.Members() {
			comp.Complete(tx.updateErr)
		}
		for _, immediate := range tx.immediateCompletions {
			immediate.comp.Complete(tx.updateErr)
		}
		return
	}
	for _, immediate := range tx.immediateCompletions {
		// Resource-level acceptance proves only this wait, not the other names
		// in older generations of the same TypeURL.
		immediate.comp.Complete(immediate.err)
	}
	noListenerWaiters.Complete(nil)
}

// registerGenerationCompletions uses the same prepared owner for the WaitGroup
// and ACK/NACK tracking. A nil snapshot denotes unpublished changes: scope
// revisions are filled from committed desired entries, without another node lookup.
func (tx *resourceTransaction) registerGenerationCompletions(snapshot cache.ResourceSnapshot, wg *completion.WaitGroup, waits typeURLWaits) {
	if wg == nil || waits.Empty() {
		return
	}
	c := tx.cache
	for typeURL, wait := range waits.All() {
		version := ""
		if snapshot == nil {
			wait.scope = wait.scope.WithRevisions(func(name string) callbacks.Revision {
				entry := tx.state.resourceWaitEntry(typeURL, name)
				if entry.resource == nil {
					entry.revision = c.completionCbs.RemovalWaitRevision(tx.state.nodeID, typeURL, name, entry.revision)
				}
				return entry.revision
			})
		} else {
			version = snapshot.GetVersion(typeURL.URL())
		}
		removalOnly := wait.scope.OnlyRemovals(func(name string) bool { return tx.state.resources[typeURL][name].resource == nil })
		owner := c.completionCbs.NewTypeGenerationCompletionOwner(tx.state.nodeID, typeURL, wait.generation, wait.scope, removalOnly)
		comp := wg.AddCompletion(owner)
		registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, version, snapshot == nil)
		if registered {
			tx.registeredCompletions.Insert(comp)
		} else {
			// Do not preallocate: immediately satisfied waits are uncommon and
			// reserving capacity adds an allocation to every resource update.
			tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletion{comp: comp, err: err})
		}
	}
}

// snapshotTypesChangedBy includes EDS because CDS can change projected CLAs
// or require an unchanged assignment to be replayed for Cluster warming.
func snapshotTypesChangedBy(changedTypeURLs typeurl.Set) typeurl.Set {
	regenerate := changedTypeURLs
	if changedTypeURLs.Has(typeurl.Cluster) {
		regenerate.Insert(typeurl.Endpoint)
	}
	return regenerate
}

// finalizePendingPublicationLocked constructs and installs a snapshot of the
// latest desired state for nodeID. The caller must hold c.mutex.
func (c *cacheImpl) finalizePendingPublicationLocked(ctx context.Context, nodeID string) error {
	state := c.getNodeState(nodeID)
	if state == nil || state.pendingPublication == nil {
		return nil
	}
	pending := state.pendingPublication

	oldSnapshot, _ := c.snapshotCache.GetSnapshot(nodeID)
	newSnapshot := c.generateSnapshotFromStateIncrementally(state, oldSnapshot, pending.changedTypeURLs)
	// SetSnapshot may synchronously queue responses. Capture this snapshot and
	// generation in their context so delayed delivery cannot associate them
	// with a newer publication. Commit callback metadata only after installation.
	err := c.snapshotCache.SetSnapshot(callbacks.WithSnapshotPublication(ctx, pending.generation, newSnapshot), nodeID, newSnapshot)
	if err != nil {
		// SnapshotCache stores the snapshot before delivering watch responses. A
		// canceled delivery may therefore return an error after publication has
		// committed; keep generation state in that case.
		currentSnapshot, getErr := c.snapshotCache.GetSnapshot(nodeID)
		// SetSnapshot stores the exact snapshot object. Version equality alone
		// cannot prove installation; do not infer success from stale state.
		committed := getErr == nil && currentSnapshot == newSnapshot
		if !committed {
			return err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}
	// Watch responses remain in Cilium's relays until after this publication
	// finishes, so expose the snapshot to callbacks only once it is committed.
	c.completionCbs.SetPublishedSnapshot(nodeID, newSnapshot)

	state.snapshotGeneration = pending.generation
	state.pendingPublication = nil
	for typeURL := range typeurl.Count {
		state.typeStates[typeURL].generation = newSnapshot.resourceGroups[typeURL].generation
		state.typeStates[typeURL].changedResourceNames.Clear()
	}
	state.rollbacks.publishedLocked(c, state, pending)
	return nil
}

func committedListenerChanges(changes resourceChanges) []ListenerChange {
	var listenerChanges []ListenerChange
	add := func(change resourceChange) {
		if change.typeURL == typeurl.Listener {
			listenerChanges = append(listenerChanges, ListenerChange{
				Previous: typedResource[*envoy_config_listener.Listener](change.previous.resource),
				Current:  typedResource[*envoy_config_listener.Listener](change.next.resource),
			})
		}
	}
	if !changes.empty() {
		add(changes.first)
	}
	for _, change := range changes.more {
		add(change)
	}
	return listenerChanges
}

// ApplyResources applies sparse removals and upserts to the cache-private
// desired state. It is the authority for semantic no-op detection, changed
// resource names and rollback policy. Changed transactions accumulate
// unpublished changes and construct a snapshot when an affected watch can
// consume it; published maps remain immutable.
func (c *cacheImpl) ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set) error {
	_, err := c.applyResources(ctx, nodeID, mutations, wg, waitTypeURLs, false)
	return err
}

func (c *cacheImpl) ApplyResourcesWithRollback(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set) (Rollback, error) {
	return c.applyResources(ctx, nodeID, mutations, wg, waitTypeURLs, true)
}

func (c *cacheImpl) applyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set, withRollback bool) (Rollback, error) {
	if err := validateResourceMutations(mutations); err != nil {
		return nil, err
	}
	state := c.getNodeState(nodeID)
	if state == nil {
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	tx := c.beginResourceTransaction(ctx, state)
	rollback, err := tx.applyResourcesLocked(mutations, wg, waitTypeURLs, withRollback)
	if err != nil {
		tx.updateErr = err
	}
	tx.complete()
	return rollback, err
}

func (c *cacheImpl) ApplyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup) error {
	_, err := c.applyResource(ctx, nodeID, typeURL, name, resource, wg, false)
	return err
}

func (c *cacheImpl) ApplyResourceWithRollback(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup) (Rollback, error) {
	return c.applyResource(ctx, nodeID, typeURL, name, resource, wg, true)
}

func (c *cacheImpl) applyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, withRollback bool) (Rollback, error) {
	if name == "" {
		return nil, errEmptyName
	}
	if typeURL >= typeurl.Count {
		return nil, fmt.Errorf("unsupported resource type index %d", typeURL)
	}
	if resource != nil {
		// Check the index before storing the protobuf under its type-specific
		// cache slot. A typed nil pointer is a removal, like an untyped nil.
		actual, err := typeurl.FromMessage(resource)
		if err != nil {
			return nil, err
		}
		if actual != typeURL {
			return nil, fmt.Errorf("resource type %s does not match %s", actual.URL(), typeURL.URL())
		}
		// Typed nil is also a removal
		if !resource.ProtoReflect().IsValid() {
			resource = nil
		}
	}

	state := c.getNodeState(nodeID)
	if state == nil {
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	tx := c.beginResourceTransaction(ctx, state)
	defer tx.complete()

	// Do not wait for network policy ACK if there are no NPDS listeners.
	if typeURL == typeurl.NetworkPolicy && wg != nil && c.listenerObserver != nil && !c.listenerObserver.HasNPDSListeners(nodeID) {
		wg = nil
	}

	previous := tx.state.resources[typeURL][name]
	if previous.resource == resource ||
		(previous.resource != nil && resource != nil && xds.ResourceEqual(previous.resource, resource)) {
		tx.state.rollbacks.supersedeCallerRollbackLocked(typeURL, name, previous)
		if !withRollback {
			tx.state.rollbacks.adoptNonRevertibleLocked(c, tx.state, typeURL, name)
		}
		if wg == nil {
			return revert.Noop, nil
		}
		// Use the canonical cache pointer for semantic no-ops, so checking ACK
		// evidence does not repeat the comparison against a fresh protobuf.
		waitEntry := tx.state.resourceWaitEntry(typeURL, name)
		if resource == nil {
			waitEntry.revision = c.completionCbs.RemovalWaitRevision(nodeID, typeURL, name, waitEntry.revision)
		}
		if tx.state.resourceGeneration == 0 && resource == nil ||
			c.completionCbs.ResourceAccepted(nodeID, typeURL, name, previous.resource, previous.resource != nil, waitEntry.revision) {
			// A pristine known node has no resource update to acknowledge. After
			// mutations, an absent name can still need ACK evidence (notably for
			// named EDS/RDS/SDS resources).
			return revert.Noop, nil
		}
		var waits typeURLWaits
		revision := waitEntry.revision
		generation := callbacks.Generation(0).MaxRevision(revision)
		if resource == nil {
			// A repeated removal may still be unpublished. Its wait must not
			// attach to an older response which contains the removed value.
			generation = tx.state.generationForType(typeURL).MaxRevision(revision)
		}
		waits.Set(typeURL, generationWait{generation: generation, scope: callbacks.SingleResourceScope(name, revision)})
		tx.awaitCurrentVersionLocked(wg, waits)
		return revert.Noop, nil
	}

	// Record listener changes for the observer when the transaction completes.
	if typeURL == typeurl.Listener {
		tx.listenerChanges = []ListenerChange{{
			Previous: typedResource[*envoy_config_listener.Listener](previous.resource),
			Current:  typedResource[*envoy_config_listener.Listener](resource),
		}}
	}
	var inverse resources
	if resource != nil {
		inverse = singleResource(typeURL, name, previous)
	}
	tx.generation = c.nextResourceGenerationLocked()
	var changes resourceChanges
	changes.add(typeURL, name, previous, resourceEntry{
		resource: resource, revision: tx.generation.Revision(), transaction: tx.generation.TransactionID(),
		nonRevertible: !withRollback,
	})

	var changedWaits typeURLWaits
	if wg != nil && !c.completionCbs.ChangedResourceAccepted(
		nodeID, typeURL, name,
		previous.resource, previous.resource != nil,
		resource, resource != nil,
		previous.revision,
	) {
		changedWaits.Set(typeURL, generationWait{generation: tx.generation, scope: callbacks.SingleResourceScope(name, tx.generation.Revision())})
	}
	if err := tx.updateResourceChangesLocked(changes, resourceUpdateOptions{
		inverse:       inverse,
		waits:         changedWaits,
		trackRollback: withRollback,
		isAPIUpdate:   true,
	}, wg); err != nil {
		return nil, err
	}
	if resource == nil {
		tx.state.rollbacks.supersedeCallerRollbackLocked(typeURL, name, resourceEntry{})
	}
	if withRollback {
		return tx.state.rollbacks.newCallerLocked(&tx, inverse, &changes), nil
	}
	return revert.Noop, nil
}

// applyResourcesLocked allocates generations and constructs transaction-fenced
// reverts inside the cache. Caller must hold mutex.
func (tx *resourceTransaction) applyResourcesLocked(mutations ResourceMutations, wg *completion.WaitGroup, waitTypeURLs typeurl.Set, withRollback bool) (Rollback, error) {
	c := tx.cache
	state := tx.state
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(mutations, c.resourceGeneration+1)
	var unchangedWaits typeURLWaits
	if changedTypeURLs.Empty() {
		if !withRollback {
			tx.adoptNonRevertibleUpsertsLocked(mutations.Upserted)
		}
		if state.resourceGeneration != 0 && wg != nil && !waitTypeURLs.Empty() {
			for typeURL := range waitTypeURLs.Members() {
				wait := tx.mutationWaitLocked(typeURL, mutations, inverse)
				if !wait.scope.HasNames() {
					continue
				}
				unchangedWaits.Set(typeURL, wait)
			}
			tx.awaitCurrentVersionLocked(wg, unchangedWaits)
		}
		state.rollbacks.supersedeCallerRollbacksLocked(state, mutations, &inverse)
		return revert.Noop, nil
	}

	tx.generation = c.nextResourceGenerationLocked()
	changes.first.next.nonRevertible = !withRollback
	for i := range changes.more {
		changes.more[i].next.nonRevertible = !withRollback
	}

	var changedWaits typeURLWaits
	if wg != nil {
		dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
		// Acceptance checks and wait scopes serve callers only. Response-owned
		// NACK rollback is prepared independently below, even without a WaitGroup.
		for typeURL := range waitTypeURLs.Members() {
			wait := tx.mutationWaitLocked(typeURL, mutations, inverse)
			if !wait.scope.HasNames() {
				continue
			}
			if dirtyTypeURLs.Has(typeURL) {
				wait.generation = tx.generation
				changedWaits.Set(typeURL, wait)
			} else {
				unchangedWaits.Set(typeURL, wait)
			}
		}
	}

	if wg != nil && !unchangedWaits.Empty() {
		tx.awaitCurrentVersionLocked(wg, unchangedWaits)
	}

	err := tx.updateResourceChangesLocked(changes, resourceUpdateOptions{
		inverse:       inverse,
		waits:         changedWaits,
		trackRollback: withRollback,
		isAPIUpdate:   true,
	}, wg)
	if err != nil {
		return nil, err
	}
	if !withRollback {
		// Adopt unchanged members only after successful admission too. A failed
		// mixed transaction must leave their earlier recovery untouched.
		tx.adoptNonRevertibleUpsertsLocked(mutations.Upserted)
	}

	state.rollbacks.supersedeCallerRollbacksLocked(state, mutations, &inverse)

	if changedTypeURLs.Has(typeurl.Listener) {
		tx.listenerChanges = committedListenerChanges(changes)
	}

	if withRollback {
		return state.rollbacks.newCallerLocked(tx, inverse, &changes), nil
	}
	return revert.Noop, nil
}

// HandleNACK uses the same transaction boundary as API mutations. Selection is
// inside the cache lock, and the entire correction commits once, finalizing only
// if a watch can consume it. complete delivers responses and resolves waits
// only after releasing that lock.
func (c *cacheImpl) HandleNACK(nodeID string, process func(callbacks.RevertBatch) error) error {
	state := c.getNodeState(nodeID)
	if state == nil {
		return fmt.Errorf("unknown xDS node %q", nodeID)
	}
	tx := c.beginResourceTransaction(context.Background(), state)
	defer tx.complete()
	return process(tx.revertLocked)
}

// revertLocked composes response-owned inverses into one prepared mutation.
// rollbacks are newest first; no lifecycle method is called which would take
// the cache lock again. Failed recovery retains all selected response owners.
func (tx *resourceTransaction) revertLocked(rollbacks []Rollback) error {
	changes, err := tx.state.rollbacks.prepareRevertLocked(tx, rollbacks)
	if err != nil {
		return err
	}
	if err := tx.applyRevertLocked(changes); err != nil {
		return err
	}
	for _, rollback := range rollbacks {
		lifecycle := rollback.(*responseRollback)
		if lifecycle.resources != nil {
			lifecycle.finalizeLocked()
		}
	}
	return nil
}

// applyRevertLocked commits caller or response recovery with fresh revisions.
// Published snapshots remain immutable; corrective publication uses the resulting
// desired state. Caller must hold the cache lock and resolve its owners afterward.
func (tx *resourceTransaction) applyRevertLocked(changes resourceChanges) error {
	c := tx.cache
	var err error
	if !changes.empty() {
		c.logger.Debug("Reverting resource changes", logfields.NodeID, tx.state.nodeID)
		tx.generation = c.nextResourceGenerationLocked()
		// Restored transaction identities retain their origins; every correction
		// gets a fresh revision, including a sent A-B-A chain whose final protobuf
		// is unchanged. Older ACKs cannot accept the newly restored named value.
		changes.first.next.revision = tx.generation.Revision()
		for i := range changes.more {
			changes.more[i].next.revision = tx.generation.Revision()
		}
		err = tx.updateResourceChangesLocked(changes, resourceUpdateOptions{}, nil)
	}
	if err == nil {
		tx.listenerChanges = committedListenerChanges(changes)
	} else {
		c.logger.Error("Failed to revert resource changes",
			logfields.NodeID, tx.state.nodeID,
			logfields.Error, err)
	}
	return err
}

// resourceMutationWait collects only unsatisfied names and their ACK-wait
// generation in one traversal. ACK evidence for unchanged names remains valid
// when another name in the same bulk TypeURL changes: waiting for those names
// again could strand the caller if subsequent responses cover only the changes.
// It returns the zero value when no names were supplied or every supplied name
// already has sufficient ACK evidence.
func resourceMutationWait[V interface {
	proto.Message
	comparable
}](completionCbs *callbacks.CompletionCallbacks, state *nodeState, typeURL typeurl.Index, removed, upserted map[string]V, inverse resources) generationWait {
	var wait generationWait
	if len(removed) == 0 && len(upserted) == 0 {
		return wait
	}
	nodeID := state.nodeID
	removalOnly := true
	// Without retained resource-level ACK evidence, every name must wait.
	// Check once rather than acquiring the callback lock for each resource.
	hasAcceptance := completionCbs.HasResourceAcceptance(nodeID, typeURL)
	waitEntry := func(name string, removal bool) resourceEntry {
		entry := state.resources[typeURL][name]
		if entry.resource == nil {
			entry.revision = state.typeStates[typeURL].revertGeneration.Revision()
			if removal {
				entry = state.resourceWaitEntry(typeURL, name)
				entry.revision = completionCbs.RemovalWaitRevision(nodeID, typeURL, name, entry.revision)
			}
		}
		return entry
	}
	addPending := func(name string, removal bool) {
		revision := waitEntry(name, removal).revision
		wait.scope.Insert(name, revision)
		wait.generation = wait.generation.MaxRevision(revision)
		removalOnly = removalOnly && removal
	}
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		if !hasAcceptance || !completionCbs.ResourceAccepted(nodeID, typeURL, name, nil, false, waitEntry(name, true).revision) {
			addPending(name, true)
		}
	}
	for name, resource := range upserted {
		desired := resourceValue(resource)
		if !hasAcceptance {
			addPending(name, desired == nil)
			continue
		}
		// Typed nil upserts remove resources, just as in prepareResourceMap.
		entry := waitEntry(name, desired == nil)
		previous := entry.resource
		var resourceAccepted bool
		if _, changed := inverse.get(typeURL, name); changed || desired == nil && previous != nil {
			resourceAccepted = completionCbs.ChangedResourceAccepted(nodeID, typeURL, name,
				previous, previous != nil, desired, desired != nil, entry.revision)
		} else {
			// Preparation already established semantic equality for this name,
			// including mixed transactions. Reuse its canonical pointer rather
			// than comparing the fresh protobuf a second time.
			resourceAccepted = completionCbs.ResourceAccepted(nodeID, typeURL, name, previous, previous != nil, entry.revision)
		}
		if !resourceAccepted {
			addPending(name, desired == nil)
		}
	}
	if !wait.scope.HasNames() {
		return generationWait{}
	}
	if removalOnly {
		wait.generation = max(wait.generation, state.generationForType(typeURL))
	}
	return wait
}

func (tx *resourceTransaction) mutationWaitLocked(typeURL typeurl.Index, mutations ResourceMutations, inverse resources) generationWait {
	c := tx.cache
	state := tx.state
	switch typeURL {
	case typeurl.Listener:
		return resourceMutationWait(c.completionCbs, state, typeURL, mutations.Removed.Listeners, mutations.Upserted.Listeners, inverse)
	case typeurl.Route:
		return resourceMutationWait(c.completionCbs, state, typeURL, mutations.Removed.Routes, mutations.Upserted.Routes, inverse)
	case typeurl.Cluster:
		return resourceMutationWait(c.completionCbs, state, typeURL, mutations.Removed.Clusters, mutations.Upserted.Clusters, inverse)
	case typeurl.Endpoint:
		return resourceMutationWait(c.completionCbs, state, typeURL, mutations.Removed.Endpoints, mutations.Upserted.Endpoints, inverse)
	case typeurl.Secret:
		return resourceMutationWait(c.completionCbs, state, typeURL, mutations.Removed.Secrets, mutations.Upserted.Secrets, inverse)
	default:
		return generationWait{}
	}
}

// resourceUpdateOptions describes rollback ownership and ACK waits for a
// prepared mutation. Its zero value is a compensating update with no new
// rollback ownership or ACK waits; API updates explicitly identify themselves
// and select whether their upserts retain response-owned rollback.
type resourceUpdateOptions struct {
	inverse resources
	waits   typeURLWaits
	// Only WithRollback API updates retain response-owned recovery.
	trackRollback bool
	// Permanent API updates discard superseded recovery; corrective reverts
	// reconcile it with restored transaction identities instead.
	isAPIUpdate bool
}

// updateResourceChangesLocked commits one prepared mutation and optionally
// publishes it for an open watch. Prepared previous entries recover failed
// admission; any requested caller lifecycle is created only after successful
// commit or publication.
// Caller must hold the cache mutex; post-lock work is accumulated on tx.
func (tx *resourceTransaction) updateResourceChangesLocked(changes resourceChanges, options resourceUpdateOptions, wg *completion.WaitGroup) error {
	c, state := tx.cache, tx.state
	changedTypeURLs := changes.typeURLs()
	oldResourceGeneration := state.resourceGeneration
	var previousReverts typeurl.Slots[callbacks.Generation]
	if !options.isAPIUpdate {
		// Caller- or response-driven reverts need a fresh corrective boundary
		// for absent-name waits, independently of API rollback policy.
		for typeURL := range changedTypeURLs.Members() {
			previousReverts[typeURL] = state.typeStates[typeURL].revertGeneration
			state.typeStates[typeURL].revertGeneration = tx.generation
		}
	}
	var oldTypeGenerations typeurl.Slots[callbacks.Generation]
	for typeURL := range typeurl.Count {
		oldTypeGenerations[typeURL] = state.typeStates[typeURL].generation
	}
	removedTypes := state.commitResourceMutation(changes, tx.generation)
	tx.registerGenerationCompletions(nil, wg, options.waits)
	oldPending, oldPendingValue, willFinalize := state.rollbacks.preparePublicationLocked(tx, changedTypeURLs, removedTypes, options)
	var err error
	if willFinalize {
		err = c.finalizePendingPublicationLocked(tx.ctx, state.nodeID)
	}
	if err != nil {
		if !options.isAPIUpdate {
			for typeURL := range changedTypeURLs.Members() {
				state.typeStates[typeURL].revertGeneration = previousReverts[typeURL]
			}
		}
		// Prepared previous entries also recover failed rollback publications,
		// without allocating inverse maps or materializing a singleton.
		if !changes.empty() {
			change := changes.first
			state.commitResourceEntry(change.typeURL, change.name, change.previous)
		}
		for _, change := range changes.more {
			state.commitResourceEntry(change.typeURL, change.name, change.previous)
		}
		state.rollbacks.restorePublicationLocked(state, oldPending, oldPendingValue)
		published, _ := c.snapshotCache.GetSnapshot(state.nodeID)
		state.reconcileChangedResourceNames(changes, published)
		state.resourceGeneration = oldResourceGeneration
		for typeURL := range typeurl.Count {
			state.typeStates[typeURL].generation = oldTypeGenerations[typeURL]
		}
	} else {
		state.resourceGeneration = tx.generation
		pruneTypes := removedTypes
		if options.isAPIUpdate && !options.trackRollback {
			pruneTypes = changedTypeURLs
		}
		for typeURL := range pruneTypes.Members() {
			if unsent := state.typeStates[typeURL].unsentRollback; unsent != nil {
				// Admitted removals end unsent recovery immediately, even when
				// publication is deferred or projects a named empty CLA.
				unsent.resources.pruneRemovedResources(state, typeURL)
				if options.isAPIUpdate && !options.trackRollback {
					// A permanent upsert breaks the earlier unsent recovery chain.
					// A subsequent revertible update must use it as its baseline.
					for name := range options.inverse.resources(typeURL) {
						delete(unsent.resources, name)
					}
				}
				if len(unsent.resources) == 0 && c.completionCbs.DiscardUnsentTypeGeneration(state.nodeID, typeURL, unsent.generation) {
					unsent.finalizeLocked()
				}
			}
		}
	}
	tx.deliveries = c.collectResponseDeliveriesLocked()
	tx.updateErr = err
	return err
}

// awaitCurrentVersionLocked registers no-op waits against published or
// unpublished desired revisions. Caller holds c.mutex; waits are completed
// after unlocking.
func (tx *resourceTransaction) awaitCurrentVersionLocked(wg *completion.WaitGroup, waits typeURLWaits) {
	if wg == nil || waits.Empty() {
		return
	}
	c, state := tx.cache, tx.state
	var unpublishedWaits, publishedWaits typeURLWaits
	for typeURL, wait := range waits.All() {
		if state.pendingPublication != nil && state.pendingPublication.changedTypeURLs.Has(typeURL) {
			unpublishedWaits.Set(typeURL, wait)
		} else {
			publishedWaits.Set(typeURL, wait)
		}
	}
	if !publishedWaits.Empty() {
		snapshot, err := c.snapshotCache.GetSnapshot(state.nodeID)
		if err == nil {
			tx.registerGenerationCompletions(snapshot, wg, publishedWaits)
		} else {
			// Before the first publication, register against desired state without
			// building a snapshot.
			if state.pendingPublication == nil {
				state.pendingPublication = &pendingPublication{
					generation: state.resourceGeneration, changedTypeURLs: typeurl.All(), watchTypeURLs: typeurl.All(),
				}
			}
			for typeURL, wait := range publishedWaits.All() {
				unpublishedWaits.Set(typeURL, wait)
			}
		}
	}
	tx.registerGenerationCompletions(nil, wg, unpublishedWaits)
}

func (c *cacheImpl) relayForLocked(responseChannel chan cache.Response) *watchRelay {
	if relay := c.watchRelays[responseChannel]; relay != nil {
		return relay
	}
	// Allow a full ADS response batch (one watch per supported type) plus an
	// immediate CreateWatch response to be queued before forwarding anything.
	// Keep at least the stream channel's capacity to avoid reducing its buffering.
	// This relies on go-control-plane's one current watch per type per ADS
	// stream. Direct cache callers sharing a channel across more watches must
	// size that channel for the maximum responses from one publication:
	// overflowing inner would block publication before we can drain it, while
	// both cache locks are still held.
	capacity := max(cap(responseChannel), int(typeurl.Count)+1)
	relay := &watchRelay{
		inner: make(chan cache.Response, capacity),
		outer: responseChannel,
	}
	c.watchRelays[responseChannel] = relay
	return relay
}

func (c *cacheImpl) addTrackedWatchLocked(state *nodeState, request *cache.Request, typeURL typeurl.Index, responseChannel chan cache.Response) *trackedWatch {
	relay := c.relayForLocked(responseChannel)
	watch := &trackedWatch{
		state:   state,
		typeURL: typeURL,
		request: request,
		relay:   relay,
	}
	watches, _ := state.openWatches.Get(watch.typeURL)
	watches.Insert(watch)
	// Sets are stored by value; persist the header when their representation
	// changes between an inline singleton and a map.
	state.openWatches.Set(watch.typeURL, watches)
	relay.watches.Insert(watch)
	return watch
}

func (c *cacheImpl) removeTrackedWatchLocked(watch *trackedWatch) {
	if watch == nil {
		return
	}
	state := watch.state
	watches, exists := state.openWatches.Get(watch.typeURL)
	if exists {
		watches.Remove(watch)
		if watches.Empty() {
			state.openWatches.Remove(watch.typeURL)
		} else {
			state.openWatches.Set(watch.typeURL, watches)
		}
	}
	if watch.relay != nil {
		watch.relay.watches.Remove(watch)
		if watch.relay.watches.Empty() && len(watch.relay.inner) == 0 {
			// Drop our reference, but close neither channel: outer belongs to
			// the stream, and a canceled go-control-plane watch may still send
			// to inner before its underlying cancellation finishes.
			delete(c.watchRelays, watch.relay.outer)
		}
	}
}

func (c *cacheImpl) cancelTrackedWatch(watch *trackedWatch) {
	c.mutex.Lock()
	if !watch.isOpen() {
		c.mutex.Unlock()
		return
	}
	cancel := watch.cancel
	// Retire tracking while serialized with publication. The underlying
	// cancellation takes go-control-plane's locks and runs after unlocking.
	c.removeTrackedWatchLocked(watch)
	c.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

// collectResponseDeliveriesLocked drains responses which go-control-plane has
// synchronously produced. Draining retires the corresponding type watch before
// another resource update can mistake it for available Envoy capacity.
// Caller holds mutex so collecting responses and retiring watches are atomic
// with respect to watch registration, cancellation, and snapshot publication.
func (c *cacheImpl) collectResponseDeliveriesLocked() []responseDelivery {
	var deliveries []responseDelivery
	for _, relay := range c.watchRelays {
		var responses []cache.Response
		for {
			select {
			case response := <-relay.inner:
				// Immediate CreateWatch responses have a background context.
				// Capture their published generation now, while no cache update
				// can interleave. The stream may not consume them until much later.
				generation := c.getNodeState(response.GetRequest().GetNode().GetId()).snapshotGeneration
				snapshot, _ := c.snapshotCache.GetSnapshot(response.GetRequest().GetNode().GetId())
				response = callbacks.WithResponseCoverage(response, generation, snapshot)
				responses = append(responses, response)
				var matched *trackedWatch
				for watch := range relay.watches.Members() {
					if watch.request == response.GetRequest() {
						matched = watch
						break
					}
				}
				if matched != nil {
					matched.state.rollbacks.claimResponseLocked(c, matched.state, matched.typeURL, response)
					c.removeTrackedWatchLocked(matched)
				}
			default:
				if len(responses) > 0 {
					deliveries = append(deliveries, responseDelivery{
						channel:   relay.outer,
						responses: responses,
					})
				}
				goto nextRelay
			}
		}
	nextRelay:
	}
	return deliveries
}

// deliverResponses synchronously hands off responses after watch bookkeeping
// is complete. Caller must have released mutex and returned from go-control-plane:
// a stream consumer may block or need to read the cache before accepting a
// response. Only the handoff may wait for that consumer, not either cache lock.
func (c *cacheImpl) deliverResponses(deliveries []responseDelivery) {
	for _, delivery := range deliveries {
		// go-control-plane's non-ADS snapshot cache has no delivery order. Sort a
		// coalesced batch by response type before handing it to the ADS stream.
		if len(delivery.responses) > 1 {
			slices.SortStableFunc(delivery.responses, func(a, b cache.Response) int {
				return cmp.Compare(cache.GetResponseType(a.GetRequest().GetTypeUrl()), cache.GetResponseType(b.GetRequest().GetTypeUrl()))
			})
		}
		for _, response := range delivery.responses {
			delivery.channel <- response
		}
	}
}

// getNodeState scans the immutable known-node set. Cilium normally serves only
// its local node, avoiding a map allocation and string hash for that case.
func (c *cacheImpl) getNodeState(nodeID string) *nodeState {
	for state := range c.nodeStates.Members() {
		if state.nodeID == nodeID {
			return state
		}
	}
	return nil
}

// HasNode uses desired-state ownership, not publication or connection state,
// to identify the consumers configured at construction. The node index is
// immutable after construction, so membership reads need no cache lock.
func (c *cacheImpl) HasNode(nodeID string) bool {
	return c.getNodeState(nodeID) != nil
}

func (c *cacheImpl) GetResource(nodeID string, typeURL typeurl.Index, resourceName string) cache_types.Resource {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.getNodeState(nodeID).getResource(typeURL, resourceName)
}

// withEpoch returns a copy-on-write protocol view using epoch while retaining
// the exact resources previously published. Resource maps are never copied.
func (snapshot *ciliumSnapshot) withEpoch(epoch uint64) *ciliumSnapshot {
	// Slots is an array, so this shallow copy isolates all state modified by
	// newCiliumSnapshot: each group's resources.Version and the snapshot epoch.
	// Immutable resource maps remain shared.
	groups := snapshot.resourceGroups
	return newCiliumSnapshot(groups, epoch)
}

func formatXDSVersion(epoch uint64, generation callbacks.Generation) string {
	// Unwrap the aggregate boundary only to encode its wire representation.
	return "e" + strconv.FormatUint(epoch, 10) + ":g" + strconv.FormatUint(uint64(generation), 10)
}

// parseXDSEpoch recognizes only versions in the form produced by
// formatXDSVersion. The generation suffix is deliberately not parsed here:
// epoch selection only needs to avoid namespaces already retained by Envoy.
func parseXDSEpoch(version string) (uint64, bool) {
	if len(version) < 3 || version[0] != 'e' {
		return 0, false
	}
	colon := strings.IndexByte(version, ':')
	if colon < 2 {
		return 0, false
	}
	for _, digit := range version[1:colon] {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	epoch, err := strconv.ParseUint(version[1:colon], 10, 64)
	return epoch, err == nil && epoch != 0
}

func singleVersion(version string) iter.Seq[string] {
	return func(yield func(string) bool) {
		yield(version)
	}
}

// prepareLiveSnapshotLocked finalizes an applicable pending publication or
// rebinds already-published resources when a later type changes the node epoch.
// Rebinding must not expose unrelated unpublished changes. Caller must hold c.mutex.
func (c *cacheImpl) prepareLiveSnapshotLocked(state *nodeState, typeURL typeurl.Index) error {
	nodeID := state.nodeID
	current, getErr := c.snapshotCache.GetSnapshot(nodeID)
	if getErr != nil && state.pendingPublication == nil {
		// Publish the known node's actual desired state, including an empty baseline.
		state.pendingPublication = &pendingPublication{
			generation:      state.resourceGeneration,
			changedTypeURLs: typeurl.All(),
			watchTypeURLs:   typeurl.All(),
		}
	}
	if state.pendingPublication != nil && (getErr != nil || state.pendingPublication.watchTypeURLs.Has(typeURL)) {
		return c.finalizePendingPublicationLocked(context.Background(), nodeID)
	}
	published, ok := current.(*ciliumSnapshot)
	if !ok || published.epoch == state.epoch {
		return nil
	}
	rebuilt := published.withEpoch(state.epoch)
	ctx := callbacks.WithSnapshotPublication(context.Background(), state.snapshotGeneration, rebuilt)
	if err := c.snapshotCache.SetSnapshot(ctx, nodeID, rebuilt); err != nil {
		installed, getErr := c.snapshotCache.GetSnapshot(nodeID)
		if getErr != nil || installed != rebuilt {
			return err
		}
	}
	c.completionCbs.SetPublishedSnapshot(nodeID, rebuilt)
	return nil
}

//
// StreamLifecycleHandler interface functions
//

// StreamStarted implements callbacks.StreamLifecycleHandler. Stream callbacks
// run outside the completion lock; known node membership never changes.
func (c *cacheImpl) StreamStarted(streamID int64, nodeID string, mode callbacks.StreamMode) {
	if mode >= callbacks.StreamModeCount {
		return
	}
	c.mutex.Lock()
	if state := c.getNodeState(nodeID); state != nil {
		state.streams[mode].Insert(streamID)
	}
	c.mutex.Unlock()
}

// StreamClosed preserves desired resources and the negotiated epoch even when
// the node is empty. Known nodes remain configured throughout the cache lifetime.
func (c *cacheImpl) StreamClosed(streamID int64, nodeID string, mode callbacks.StreamMode) {
	if mode >= callbacks.StreamModeCount {
		return
	}
	c.mutex.Lock()
	if state := c.getNodeState(nodeID); state != nil {
		state.streams[mode].Remove(streamID)
	}
	c.mutex.Unlock()
}

//
// SnapshotCache interface functions
//
// These forward to the contained SnapshotCache after taking c.mutex for mutating operations or
// synchronization.
//

var (
	errUnimplemented = errors.New("unimplemented")
	errNilRequest    = errors.New("nil xDS request")
)

func (c *cacheImpl) Fetch(_ context.Context, _ *cache.Request) (cache.Response, error) {
	return nil, errUnimplemented
}

func (c *cacheImpl) CreateDeltaWatch(_ *cache.DeltaRequest, _ cache.Subscription, _ chan cache.DeltaResponse) (cancel func(), err error) {
	return nil, errUnimplemented
}

// CreateWatch requires the non-nil subscription supplied by go-control-plane.
func (c *cacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	if request == nil {
		return nil, errNilRequest
	}
	nodeID := request.GetNode().GetId()
	state := c.getNodeState(nodeID)
	if state == nil {
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	typeURL, supported := typeurl.FromURL(request.GetTypeUrl())
	if !supported {
		// Unknown protocol types are outside Cilium's fixed ADS resource set.
		// Preserve go-control-plane behavior without creating internal tracking
		// state which could never be addressed by an indexed mutation.
		return c.snapshotCache.CreateWatch(request, sub, respChan)
	}
	// Empty named subscriptions are not wildcard subscriptions. In particular,
	// EDS, RDS and SDS can unsubscribe by sending an empty list. The server has
	// already processed any ACK/NACK before creating this watch. Do not let
	// go-control-plane interpret the empty request names as a full-state request,
	// or retain a watch that could trigger unnecessary snapshot publication.
	if !sub.IsWildcard() && len(sub.SubscribedResources()) == 0 {
		return func() {}, nil
	}

	// go-control-plane parses "*" as a wildcard, but SnapshotCache filters
	// resources and checks ADS request coverage using literal request names.
	// Use its empty-name wildcard spelling for every supported type. Current
	// Envoy clients already send empty wildcard names, so this is defensive.
	if sub.IsWildcard() && len(request.GetResourceNames()) > 0 {
		// Share read-only known fields in a fresh protobuf: a struct copy would copy
		// protobuf runtime state, while proto.Clone would deep-copy needlessly.
		request = &cache.Request{
			VersionInfo:      request.VersionInfo,
			Node:             request.Node,
			ResourceLocators: request.ResourceLocators,
			TypeUrl:          request.TypeUrl,
			ResponseNonce:    request.ResponseNonce,
			ErrorDetail:      request.ErrorDetail,
		}
	}

	c.mutex.Lock()
	if err := state.selectEpochLocked(typeURL, singleVersion(request.GetVersionInfo())); err != nil {
		c.mutex.Unlock()
		return nil, err
	}
	if err := c.prepareLiveSnapshotLocked(state, typeURL); err != nil {
		deliveries := c.collectResponseDeliveriesLocked()
		c.mutex.Unlock()
		c.deliverResponses(deliveries)
		return nil, err
	}
	state.commitEpochNegotiation(typeURL)
	// Register before calling go-control-plane: CreateWatch may immediately
	// queue a response rather than establish a deferred watch. Its relay keeps
	// that response buffered until we retire the watch and release the locks.
	watch := c.addTrackedWatchLocked(state, request, typeURL, respChan)
	watch.cancel, err = c.snapshotCache.CreateWatch(request, sub, watch.relay.inner)
	if err != nil {
		c.removeTrackedWatchLocked(watch)
	}
	deliveries := c.collectResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	if err != nil {
		return nil, err
	}
	return func() { c.cancelTrackedWatch(watch) }, nil
}

// SetSnapshot serializes publication and hands off responses only after both
// cacheImpl and the contained SnapshotCache locks have been released.
func (c *cacheImpl) SetSnapshot(ctx context.Context, nodeID string, snapshot cache.ResourceSnapshot) error {
	c.mutex.Lock()
	if c.getNodeState(nodeID) == nil {
		c.mutex.Unlock()
		return fmt.Errorf("unknown xDS node %q", nodeID)
	}
	err := c.snapshotCache.SetSnapshot(ctx, nodeID, snapshot)
	// Collect even on error: go-control-plane may already have installed the
	// snapshot and queued some responses before failing a later delivery.
	deliveries := c.collectResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	return err
}

func (c *cacheImpl) GetSnapshot(node string) (cache.ResourceSnapshot, error) {
	return c.snapshotCache.GetSnapshot(node)
}

// ClearSnapshot is unsupported because publication and ACK/NACK bookkeeping
// must remain synchronized with desired state.
func (*cacheImpl) ClearSnapshot(string) {
	panic("ClearSnapshot is unsupported by the Cilium ADS cache")
}

func (c *cacheImpl) GetStatusInfo(node string) cache.StatusInfo {
	return c.snapshotCache.GetStatusInfo(node)
}

func (c *cacheImpl) GetStatusKeys() []string {
	return c.snapshotCache.GetStatusKeys()
}
