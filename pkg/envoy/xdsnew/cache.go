// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"hash/fnv"
	"iter"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_filters_network_tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	controlplanelog "github.com/envoyproxy/go-control-plane/pkg/log"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/rand"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = typeurl.NetworkPolicyURL
	NetworkPolicyHostsTypeURL = typeurl.NetworkPolicyHostsURL
	logFieldComponent         = "component"
)

type RevertGenerationFunc = callbacks.RevertGenerationFunc
type Rollback = callbacks.Rollback

// TypeURLCallbacks stores optional completion callbacks for supported resource
// types without allocating a string-keyed map.
type TypeURLCallbacks = typeurl.Map[func(error)]

// NewTypeURLCallbacks returns an explicitly initialized empty callback set.
// This differs from the zero value, which asks ApplyResources to infer the
// default Listener ACK wait when a listener is mutated.
func NewTypeURLCallbacks() TypeURLCallbacks {
	return typeurl.NewMap[func(error)]()
}

// ResourceMutations is a sparse transaction for Envoy's Listener, Route,
// Cluster, Endpoint, and Secret resources. NPDS/NPHDS are updated only through
// typed cache APIs, so they cannot share a transaction with a Listener.
// Unchanged resource maps remain nil. Keeping the Resources values inline lets
// callers keep the sparse headers on their stack; only referenced maps escape.
type ResourceMutations struct {
	Removed  xds.Resources
	Upserted xds.Resources
}

// resourceChange is one semantic change to the cache-private desired state.
// The protobufs are immutable; a nil resource removes the named resource.
// previous is retained only while preparing the transaction or its inverse.
type resourceChange struct {
	typeURL  typeurl.Index
	name     string
	previous resourceEntry
	resource cache_types.Resource
}

// resourceChanges keeps the common single-resource transaction inline. Bulk
// transactions use one slice instead of separate removed and upserted maps
// for every resource type. Empty names are rejected at the API
// boundary, so the first change's name also indicates whether it is present.
type resourceChanges struct {
	first resourceChange
	more  []resourceChange
	types typeurl.Set
}

func (changes *resourceChanges) add(typeURL typeurl.Index, name string, previous resourceEntry, resource cache_types.Resource) {
	change := resourceChange{typeURL: typeURL, name: name, previous: previous, resource: resource}
	if changes.first.name == "" {
		changes.first = change
	} else {
		changes.more = append(changes.more, change)
	}
	changes.types.Insert(typeURL)
}

func (changes resourceChanges) empty() bool {
	return changes.first.name == ""
}

func (changes resourceChanges) typeURLs() typeurl.Set {
	if !changes.types.Known() {
		return typeurl.NewSet()
	}
	return changes.types
}

func (changes resourceChanges) inverse() inverseResources {
	if changes.empty() {
		return inverseResources{}
	}
	if len(changes.more) == 0 {
		return singleInverseEntry(changes.first.typeURL, changes.first.name, changes.first.previous)
	}
	var inverse inverseResources
	add := func(change resourceChange) {
		entries := inverse.entries[change.typeURL]
		if entries == nil {
			entries = make(map[string]resourceEntry)
			inverse.entries[change.typeURL] = entries
		}
		entries[change.name] = change.previous
	}
	add(changes.first)
	for _, change := range changes.more {
		add(change)
	}
	return inverse
}

// ListenerChange describes one committed listener transition. Previous is nil
// for an insertion and Current is nil for a removal. Resources are immutable
// cache-owned protobufs.
type ListenerChange struct {
	Previous *envoy_config_listener.Listener
	Current  *envoy_config_listener.Listener
}

// snapshotGenerator constructs the immutable snapshot which represents the
// latest staged resources. Keeping construction behind this callback lets the
// cache postpone protobuf marshaling and version hashing until Envoy has a
// watch which can consume the result.
type snapshotGenerator func(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error)

type Cache interface {
	cache.SnapshotCache

	// ApplyResources stages the newest immutable resource state if it contains
	// semantic changes. Completions for unchanged resource types are attached to
	// their current version instead of creating a completion-only generation.
	// On change it returns a caller-owned rollback lifecycle. The caller must
	// eventually call exactly one of Finalize or Revert; cache-owned NACK
	// rollback remains live independently until the response is accepted or
	// rejected.
	ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (bool, Rollback, error)
	// Typed single-resource updates compare only the named resource and build a
	// sparse mutation only after detecting an actual semantic change.
	UpsertListener(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error)
	RemoveListener(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error)
	UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error)
	RemoveNetworkPolicy(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error)
	// RemoveAllNetworkPolicies removes only NPDS resources for this node in one
	// cache transaction. Generic Envoy-resource mutations cannot include NPDS.
	RemoveAllNetworkPolicies(ctx context.Context, nodeID string) (bool, Rollback, error)
	UpsertNetworkPolicyHosts(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (bool, Rollback, error)
	RemoveNetworkPolicyHosts(ctx context.Context, nodeID, name string) (bool, Rollback, error)
	// GetResource returns one cache-owned immutable resource without
	// materializing the complete desired resource maps.
	GetResource(nodeID string, typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool)
	// Resource iterators expose cache-owned immutable resources without
	// constructing xds.Resources or leaking the mutable internal maps. Iteration
	// holds the cache read lock, so loop bodies must not call back into the cache.
	Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener]
	Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration]
	NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy]
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
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

// WithListenerObserver supplies listener-derived NPDS wait decisions to the
// cache. A nil observer leaves standalone cache users' explicit waits intact.
func WithListenerObserver(observer ListenerObserver) CacheOption {
	return func(c *cacheImpl) {
		c.listenerObserver = observer
	}
}

type cacheImpl struct {
	cache.SnapshotCache

	// mutex protects cache state and serializes complete resource mutations.
	// Mutations hold the write lock from semantic comparison through staging or
	// publication, then release it before delivering responses or completions.
	mutex *lock.RWMutex
	// nodeStates hold the private mutable desired resources and the names changed
	// since the last snapshot publication for each node.
	nodeStates map[string]*nodeState
	// openWatches tracks the precise resource types which can consume a newly
	// finalized snapshot. go-control-plane exposes only a total watch count, so
	// responses are relayed through cache-owned channels to retire each watch as
	// soon as it is consumed.
	openWatches   map[string]*nodeWatchState
	watchRelays   map[chan cache.Response]*watchRelay
	nextWatchID   uint64
	logger        *slog.Logger
	strictAdsMode bool
	completionCbs *callbacks.CompletionCallbacks
	// resourceGeneration is the global resource-state sequence protected by
	// mutex.
	resourceGeneration uint64
	// listenerObserver is supplied by the ADS server. A nil observer leaves
	// standalone cache users' explicit ACK waits unchanged.
	listenerObserver ListenerObserver
	// defaultGenerator is bound once when the cache is constructed. Reusing the
	// method value avoids allocating an otherwise identical closure for every
	// resource mutation.
	defaultGenerator snapshotGenerator
}

type stagedSnapshot struct {
	generation uint64
	// changedTypeURLs includes dependent types whose version context may need
	// regeneration. watchTypeURLs contains the directly mutated types which can
	// justify publishing the staged snapshot when Envoy has capacity for them.
	changedTypeURLs    typeurl.Set
	watchTypeURLs      typeurl.Set
	completionTypeURLs typeurl.Set
	rollbacks          typeurl.Map[rollbackResources]
	generator          snapshotGenerator
}

// nodeState separates the mutable cache-private desired state from the last
// immutable snapshot published to Envoy. Each resource type retains only the
// names touched since publication, allowing finalization to update the
// published go-control-plane maps without traversing the complete desired
// state.
type nodeState struct {
	// resourceGeneration identifies the latest desired state, while
	// snapshotGeneration identifies the state most recently published to Envoy.
	resourceGeneration uint64
	snapshotGeneration uint64
	// resources owns the current desired state, including generation-tagged
	// removal tombstones, and the sparse set of names which may differ from the
	// last published snapshot.
	resources cacheResources
	// staged is non-nil while pending resources have not yet been finalized
	// into a go-control-plane snapshot.
	staged *stagedSnapshot
	// unsentRollbacks retains at most one coalesced response rollback per
	// resource type until go-control-plane produces a response carrying it.
	// Once a response is observed, ownership moves exclusively to the
	// completion callbacks until ACK or NACK.
	unsentRollbacks typeurl.Map[*rollbackLifecycle]
	// rollbackOwners counts live caller- and cache-owned rollback handles.
	// Removal tombstones can be discarded once their last owner terminates.
	rollbackOwners rollbackOwners
}

// resourceEntry keeps the immutable protobuf and the generation which most
// recently changed its name together. A nil resource is a removal tombstone;
// retaining its generation makes remove/recreate/remove ABA sequences safe.
// The entry is stored by value so changing one resource does not allocate a
// wrapper object.
type resourceEntry struct {
	resource   cache_types.Resource
	generation uint64
}

// resourceTypeState groups the desired resource entries and names changed
// since publication for one TypeURL.
type resourceTypeState struct {
	entries map[string]resourceEntry
	changed set.Set[string]
}

// cacheResources is the cache-private, generation-aware counterpart of
// xds.Resources. It deliberately excludes PortAllocationCallbacks, which are
// server-side listener bookkeeping rather than xDS resources. The TypeURL slot
// determines the concrete generated protobuf type stored in each map.
type cacheResources typeurl.Slots[resourceTypeState]

// resourceEntrySlots carries sparse resource entries without the persistent
// changed-name sets owned by cacheResources.
type resourceEntrySlots typeurl.Slots[map[string]resourceEntry]

// inverseResources stores the overwhelmingly common single-resource inverse
// inline. Broader transactions retain ordinary per-TypeURL maps. The two
// representations are mutually exclusive.
type inverseResources struct {
	entries   typeurl.Slots[map[string]resourceEntry]
	singleton resourceEntrySingleton
}

type resourceEntrySingleton struct {
	name    string
	entry   resourceEntry
	typeURL typeurl.Index
}

func singleInverseEntry(typeURL typeurl.Index, name string, entry resourceEntry) inverseResources {
	return inverseResources{singleton: resourceEntrySingleton{
		name:    name,
		entry:   entry,
		typeURL: typeURL,
	}}
}

func (inverse *inverseResources) get(typeURL typeurl.Index, name string) (resourceEntry, bool) {
	if inverse.hasSingleton() {
		if inverse.singleton.typeURL == typeURL && inverse.singleton.name == name {
			return inverse.singleton.entry, true
		}
		return resourceEntry{}, false
	}
	entry, exists := inverse.entries[typeURL][name]
	return entry, exists
}

func (inverse *inverseResources) hasSingleton() bool {
	return inverse.singleton.name != ""
}

func (inverse *inverseResources) len(typeURL typeurl.Index) int {
	if inverse.hasSingleton() {
		if inverse.singleton.typeURL == typeURL {
			return 1
		}
		return 0
	}
	return len(inverse.entries[typeURL])
}

func (inverse *inverseResources) resources(typeURL typeurl.Index) iter.Seq2[string, resourceEntry] {
	return func(yield func(string, resourceEntry) bool) {
		if inverse.hasSingleton() {
			if inverse.singleton.typeURL == typeURL {
				yield(inverse.singleton.name, inverse.singleton.entry)
			}
			return
		}
		for name, entry := range inverse.entries[typeURL] {
			if !yield(name, entry) {
				return
			}
		}
	}
}

func (inverse *inverseResources) empty() bool {
	if inverse.hasSingleton() {
		return false
	}
	for typeURL := range typeurl.Indices() {
		if len(inverse.entries[typeURL]) != 0 {
			return false
		}
	}
	return true
}

// materialize is used only to recover from snapshot publication failure. The
// normal mutation and finalize paths retain the allocation-free singleton.
func (inverse *inverseResources) materialize() resourceEntrySlots {
	if inverse.hasSingleton() {
		var entries resourceEntrySlots
		entries[inverse.singleton.typeURL] = map[string]resourceEntry{
			inverse.singleton.name: inverse.singleton.entry,
		}
		return entries
	}
	return resourceEntrySlots(inverse.entries)
}

func (state *nodeState) resourceEntries(typeURL typeurl.Index) map[string]resourceEntry {
	if state == nil {
		return nil
	}
	return state.resources[typeURL].entries
}

type rollbackOwnerKey struct {
	name       string
	generation uint64
}

// rollbackOwners groups tombstone ownership by the fixed resource type before
// indexing individual resource generations. The zero value is empty.
type rollbackOwners = typeurl.Map[map[rollbackOwnerKey]uint32]

func (state *nodeState) rollbackOwnerCount(typeURL typeurl.Index, key rollbackOwnerKey) uint32 {
	owners, _ := state.rollbackOwners.Get(typeURL)
	return owners[key]
}

func (state *nodeState) addRollbackOwner(typeURL typeurl.Index, key rollbackOwnerKey) {
	owners, _ := state.rollbackOwners.Get(typeURL)
	if owners == nil {
		owners = make(map[rollbackOwnerKey]uint32)
		state.rollbackOwners.Set(typeURL, owners)
	}
	owners[key]++
}

func (state *nodeState) removeRollbackOwner(typeURL typeurl.Index, key rollbackOwnerKey) {
	owners, exists := state.rollbackOwners.Get(typeURL)
	if !exists {
		return
	}
	count := owners[key]
	if count > 1 {
		owners[key] = count - 1
		return
	}
	delete(owners, key)
	if len(owners) == 0 {
		state.rollbackOwners.Remove(typeURL)
	}
}

type rollbackEntry struct {
	previous           resourceEntry
	expectedGeneration uint64
}

type rollbackResources typeurl.Slots[map[string]rollbackEntry]

type rollbackLifecycle struct {
	cache      *cacheImpl
	ctx        context.Context
	nodeID     string
	typeURL    typeurl.Index
	generation uint64
	resources  *rollbackResources
	inverse    inverseResources
}

type nodeWatchState = typeurl.Map[map[uint64]*trackedWatch]

type watchRelay struct {
	inner   chan cache.Response
	outer   chan cache.Response
	watches map[uint64]*trackedWatch
}

type trackedWatch struct {
	id             uint64
	nodeID         string
	typeURL        typeurl.Index
	streamID       int64
	request        *cache.Request
	backendRequest *cache.Request
	relay          *watchRelay
	cancel         func()
}

// isReset reports whether this watch is currently bound through its cloned,
// stream-private request rather than the original protocol request.
func (watch *trackedWatch) isReset() bool {
	return watch.backendRequest != watch.request
}

// isOpen reports whether the watch is still owned by its relay. Caller must
// hold cacheImpl.mutex.
func (watch *trackedWatch) isOpen() bool {
	return watch != nil && watch.relay != nil && watch.relay.watches[watch.id] == watch
}

// trackedResponse restores the protocol request after a stream-reset watch was
// keyed under a synthetic node ID, and marks the response as transport-only so
// completion callbacks do not resolve desired cache generations from it.
type trackedResponse struct {
	cache.Response
	request *cache.Request
	ctx     context.Context
}

func (response *trackedResponse) GetRequest() *cache.Request {
	return response.request
}

func (response *trackedResponse) GetContext() context.Context {
	return response.ctx
}

type responseDelivery struct {
	channel   chan cache.Response
	responses []cache.Response
}

var _ Cache = &cacheImpl{}

// snapshotResourceGroup keeps the published resources and their per-resource
// versions together. Every resource in resources.Items has a corresponding
// entry in versions.
type snapshotResourceGroup struct {
	resources cache.Resources
	versions  map[string]string
}

// ciliumSnapshot implements go-control-plane's ResourceSnapshot interface for
// both Envoy core resources and Cilium-specific xDS resources. Resource groups
// are the published copy-on-write state in the same representations used by
// go-control-plane's native Snapshot, so its version maps do not need to be
// reconstructed after finalization.
type ciliumSnapshot typeurl.Slots[snapshotResourceGroup]

// Ensure ciliumSnapshot implements cache.ResourceSnapshot.
var _ cache.ResourceSnapshot = &ciliumSnapshot{}
var _ interface{ Consistent() error } = &ciliumSnapshot{}

var (
	listenerDependentTypeURLs = typeurl.NewSet(typeurl.Route, typeurl.Cluster, typeurl.Secret)
	clusterDependentTypeURLs  = typeurl.NewSet(typeurl.Endpoint, typeurl.Secret)
)

func newCiliumSnapshot(resourceGroups typeurl.Slots[snapshotResourceGroup]) *ciliumSnapshot {
	snapshot := ciliumSnapshot(resourceGroups)
	return &snapshot
}

func (w *ciliumSnapshot) GetVersion(typeURLString string) string {
	typeURL, ok := typeurl.FromURL(typeURLString)
	if !ok {
		return ""
	}
	return w[typeURL].resources.Version
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
	return w[typeURL].resources.Items
}

func (w *ciliumSnapshot) ConstructVersionMap() error {
	if w == nil {
		return fmt.Errorf("missing snapshot")
	}
	return nil
}

func (w *ciliumSnapshot) GetVersionMap(typeURLString string) map[string]string {
	if w == nil {
		return nil
	}
	typeURL, ok := typeurl.FromURL(typeURLString)
	if !ok {
		return nil
	}
	return w[typeURL].versions
}

func (w *ciliumSnapshot) Consistent() error {
	if w == nil {
		return fmt.Errorf("nil snapshot")
	}

	var resourceGroups [cache_types.UnknownType]cache.Resources
	for typeURL := range typeurl.Indices() {
		resources := w[typeURL].resources
		responseType := cache.GetResponseType(envoy_resource.Type(typeURL.URL()))
		if responseType == cache_types.UnknownType {
			continue
		}
		resourceGroups[responseType] = resources
	}

	referencedResources := cache.GetAllResourceReferences(resourceGroups)
	for _, responseType := range []cache_types.ResponseType{cache_types.Endpoint, cache_types.Route} {
		typeURL, err := cache.GetResponseTypeURL(responseType)
		if err != nil {
			return err
		}

		resources := resourceGroups[responseType]
		references := referencedResources[typeURL]
		if len(references) != len(resources.Items) {
			return fmt.Errorf("mismatched %q reference and resource lengths: len(%v) != %d",
				typeURL, references, len(resources.Items))
		}
		for name := range references {
			if _, ok := resources.Items[name]; !ok {
				return fmt.Errorf("inconsistent %q reference: missing resource %q", typeURL, name)
			}
		}
	}

	return nil
}

// CheckSnapshotConsistency verifies that a generated ADS snapshot has all referenced Envoy resources.
func CheckSnapshotConsistency(snapshot cache.ResourceSnapshot) error {
	checker, ok := snapshot.(interface{ Consistent() error })
	if !ok {
		return fmt.Errorf("snapshot %T does not support consistency checks", snapshot)
	}
	return checker.Consistent()
}

func snapshotCacheLogger(logger *slog.Logger) controlplanelog.Logger {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With(logFieldComponent, "go-control-plane-snapshot-cache")

	// Empty logger for disabled debug level
	debugLogger := func(string, ...any) {}
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		debugLogger = func(format string, args ...any) {
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

func NewCache(logger *slog.Logger, strictAdsMode bool, options ...CacheOption) Cache {
	snapshotCache := cache.NewSnapshotCache(strictAdsMode, cache.IDHash{}, snapshotCacheLogger(logger))

	c := &cacheImpl{
		SnapshotCache: snapshotCache,
		mutex:         &lock.RWMutex{},
		nodeStates:    make(map[string]*nodeState),
		openWatches:   make(map[string]*nodeWatchState),
		watchRelays:   make(map[chan cache.Response]*watchRelay),
		logger:        logger,
		strictAdsMode: strictAdsMode,
		completionCbs: callbacks.NewCompletionCallbacks(logger),
	}
	for _, option := range options {
		option(c)
	}
	c.defaultGenerator = c.generateSnapshotForUpdate
	c.completionCbs.SetStreamClosedCallback(c.streamClosed)
	return c
}

func (c *cacheImpl) hash(resources map[string]string) string {
	hasher := fnv.New32a()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(hasher, "%#v", resources)
	return rand.SafeEncodeString(fmt.Sprint(hasher.Sum32()))
}

func addResourceReference(refs map[string]map[string]struct{}, parent, resource string) {
	if parent == "" || resource == "" {
		return
	}
	if refs[parent] == nil {
		refs[parent] = make(map[string]struct{})
	}
	refs[parent][resource] = struct{}{}
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func resourceReferencesVersionContext(refs map[string]map[string]struct{}) string {
	parents := sortedMapKeys(refs)

	var sb strings.Builder
	for _, parent := range parents {
		children := sortedMapKeys(refs[parent])
		for _, child := range children {
			sb.WriteString(parent)
			sb.WriteByte(0)
			sb.WriteString(child)
			sb.WriteByte(0)
		}
	}
	return sb.String()
}

type snapshotResourceView interface {
	listeners() iter.Seq2[string, *envoy_config_listener.Listener]
	clusters() iter.Seq2[string, *envoy_config_cluster.Cluster]
}

type cacheSnapshotResourceView struct {
	resources *cacheResources
}

func (view cacheSnapshotResourceView) listeners() iter.Seq2[string, *envoy_config_listener.Listener] {
	return func(yield func(string, *envoy_config_listener.Listener) bool) {
		for name, entry := range view.resources[typeurl.Listener].entries {
			if entry.resource != nil && !yield(name, typedResource[*envoy_config_listener.Listener](entry.resource)) {
				return
			}
		}
	}
}

func (view cacheSnapshotResourceView) clusters() iter.Seq2[string, *envoy_config_cluster.Cluster] {
	return func(yield func(string, *envoy_config_cluster.Cluster) bool) {
		for name, entry := range view.resources[typeurl.Cluster].entries {
			if entry.resource != nil && !yield(name, typedResource[*envoy_config_cluster.Cluster](entry.resource)) {
				return
			}
		}
	}
}

func edsClusterReferenceVersionContext(resources snapshotResourceView) string {
	refs := make(map[string]map[string]struct{})
	for name, cluster := range resources.clusters() {
		if cluster.GetType() != envoy_config_cluster.Cluster_EDS {
			continue
		}

		// Use the snapshot map key as the parent identity. CEC parsing may
		// qualify the snapshot resource key while leaving the inner Envoy name
		// or EDS service name shared across multiple generated clusters; the key
		// is what makes a newly introduced parent visible to versioning.
		serviceName := cluster.GetEdsClusterConfig().GetServiceName()
		if serviceName == "" {
			serviceName = cluster.GetName()
		}
		if serviceName == "" {
			serviceName = name
		}
		addResourceReference(refs, name, serviceName)
	}

	return resourceReferencesVersionContext(refs)
}

func httpConnectionManagerFromFilter(filter *envoy_config_listener.Filter) *envoy_config_http.HttpConnectionManager {
	typedConfig := filter.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	hcm, _ := msg.(*envoy_config_http.HttpConnectionManager)
	return hcm
}

func rdsListenerReferenceVersionContext(resources snapshotResourceView) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.listeners() {
		for _, filterChain := range listener.GetFilterChains() {
			for _, filter := range filterChain.GetFilters() {
				hcm := httpConnectionManagerFromFilter(filter)
				if hcm == nil {
					continue
				}
				addResourceReference(refs, name, hcm.GetRds().GetRouteConfigName())
			}
		}
	}

	return resourceReferencesVersionContext(refs)
}

func addSDSSecretConfigReference(refs map[string]map[string]struct{}, parent string, secretConfig *envoy_config_tls.SdsSecretConfig) {
	addResourceReference(refs, parent, secretConfig.GetName())
}

func addCommonTLSContextSDSReferences(refs map[string]map[string]struct{}, parent string, commonTLSContext *envoy_config_tls.CommonTlsContext) {
	if commonTLSContext == nil {
		return
	}
	for _, secretConfig := range commonTLSContext.GetTlsCertificateSdsSecretConfigs() {
		addSDSSecretConfigReference(refs, parent, secretConfig)
	}
	addSDSSecretConfigReference(refs, parent, commonTLSContext.GetValidationContextSdsSecretConfig())
	addSDSSecretConfigReference(refs, parent, commonTLSContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig())
}

func addDownstreamTLSContextSDSReferences(refs map[string]map[string]struct{}, parent string, downstreamTLSContext *envoy_config_tls.DownstreamTlsContext) {
	if downstreamTLSContext == nil {
		return
	}
	addCommonTLSContextSDSReferences(refs, parent, downstreamTLSContext.GetCommonTlsContext())
	addSDSSecretConfigReference(refs, parent, downstreamTLSContext.GetSessionTicketKeysSdsSecretConfig())
}

func addUpstreamTLSContextSDSReferences(refs map[string]map[string]struct{}, parent string, upstreamTLSContext *envoy_config_tls.UpstreamTlsContext) {
	if upstreamTLSContext == nil {
		return
	}
	addCommonTLSContextSDSReferences(refs, parent, upstreamTLSContext.GetCommonTlsContext())
}

func downstreamTLSContextFromTransportSocket(transportSocket *envoy_config_core.TransportSocket) *envoy_config_tls.DownstreamTlsContext {
	typedConfig := transportSocket.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	downstreamTLSContext, _ := msg.(*envoy_config_tls.DownstreamTlsContext)
	return downstreamTLSContext
}

func upstreamTLSContextFromTransportSocket(transportSocket *envoy_config_core.TransportSocket) *envoy_config_tls.UpstreamTlsContext {
	typedConfig := transportSocket.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	upstreamTLSContext, _ := msg.(*envoy_config_tls.UpstreamTlsContext)
	return upstreamTLSContext
}

func tcpProxyFromFilter(filter *envoy_config_listener.Filter) *envoy_extensions_filters_network_tcp_proxy.TcpProxy {
	typedConfig := filter.GetTypedConfig()
	if typedConfig == nil {
		return nil
	}
	msg, err := typedConfig.UnmarshalNew()
	if err != nil {
		return nil
	}
	tcpProxy, _ := msg.(*envoy_extensions_filters_network_tcp_proxy.TcpProxy)
	return tcpProxy
}

func listenerClusterReferenceVersionContext(resources snapshotResourceView) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.listeners() {
		for _, filterChain := range listener.GetFilterChains() {
			for _, filter := range filterChain.GetFilters() {
				tcpProxy := tcpProxyFromFilter(filter)
				if tcpProxy == nil {
					continue
				}
				addResourceReference(refs, name, tcpProxy.GetCluster())
				for _, cluster := range tcpProxy.GetWeightedClusters().GetClusters() {
					addResourceReference(refs, name, cluster.GetName())
				}
			}
		}
	}
	return resourceReferencesVersionContext(refs)
}

func sdsReferenceVersionContext(resources snapshotResourceView) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.listeners() {
		for _, filterChain := range listener.GetFilterChains() {
			addDownstreamTLSContextSDSReferences(refs, name, downstreamTLSContextFromTransportSocket(filterChain.GetTransportSocket()))
		}
	}
	for name, cluster := range resources.clusters() {
		addUpstreamTLSContextSDSReferences(refs, name, upstreamTLSContextFromTransportSocket(cluster.GetTransportSocket()))
	}

	return resourceReferencesVersionContext(refs)
}

func resourceContentVersion(resource cache_types.Resource) (string, error) {
	marshaledResource, err := cache.MarshalResource(resource)
	if err != nil {
		return "", err
	}
	return cache.HashResource(marshaledResource), nil
}

func (c *cacheImpl) resourceVersion(typeURL typeurl.Index, resourceVersions map[string]string, versionContext ...string) string {
	keys := sortedMapKeys(resourceVersions)
	var sb strings.Builder
	for _, name := range keys {
		sb.WriteString(name)
		sb.WriteByte(0)
		sb.WriteString(resourceVersions[name])
		sb.WriteByte(0)
	}
	for _, context := range versionContext {
		if context == "" {
			continue
		}
		sb.WriteString("version-context")
		sb.WriteByte(0)
		sb.WriteString(context)
		sb.WriteByte(0)
	}
	return c.hash(map[string]string{typeURL.URL(): sb.String()})
}

func snapshotVersionContext(resources snapshotResourceView, typeURL typeurl.Index) string {
	switch typeURL {
	case typeurl.Endpoint:
		// Envoy creates one EDS subscription per EDS-backed cluster. A new
		// parent can request a dependent resource that the ADS stream has already
		// seen at the current version, so go-control-plane may open the new watch
		// without replaying the cached resource. Include the parent reference sets
		// in dependent resource versions so new subscriptions receive the current
		// resource immediately.
		return edsClusterReferenceVersionContext(resources)
	case typeurl.Route:
		return rdsListenerReferenceVersionContext(resources)
	case typeurl.Secret:
		return sdsReferenceVersionContext(resources)
	case typeurl.Cluster:
		return listenerClusterReferenceVersionContext(resources)
	default:
		return ""
	}
}

func incrementalSnapshotTypeURLs(changedTypeURLs typeurl.Set) (typeurl.Set, bool) {
	if !changedTypeURLs.Known() {
		return typeurl.Set{}, false
	}
	regenerate := changedTypeURLs
	if changedTypeURLs.Has(typeurl.Listener) {
		regenerate = regenerate.Union(listenerDependentTypeURLs)
	}
	if changedTypeURLs.Has(typeurl.Cluster) {
		regenerate = regenerate.Union(clusterDependentTypeURLs)
	}

	return regenerate, true
}

func (c *cacheImpl) canGenerateSnapshotIncrementally(previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (*ciliumSnapshot, typeurl.Set, bool) {
	previousSnapshot, ok := previous.(*ciliumSnapshot)
	if !ok || previousSnapshot == nil {
		return nil, typeurl.Set{}, false
	}
	regenerate, ok := incrementalSnapshotTypeURLs(changedTypeURLs)
	return previousSnapshot, regenerate, ok
}

func (c *cacheImpl) resourceGroupFromEntries(typeURL typeurl.Index, resources map[string]resourceEntry, versionContext string) (cache.Resources, map[string]string, error) {
	items := make(map[string]cache_types.ResourceWithTTL, len(resources))
	versions := make(map[string]string, len(resources))
	for name, entry := range resources {
		if entry.resource == nil {
			continue
		}
		version, err := resourceContentVersion(entry.resource)
		if err != nil {
			return cache.Resources{}, nil, err
		}
		items[name] = cache_types.ResourceWithTTL{Resource: entry.resource}
		versions[name] = version
	}
	if len(items) == 0 {
		items = nil
	}
	if len(versions) == 0 {
		versions = nil
	}
	return cache.Resources{
		Version: c.resourceVersion(typeURL, versions, versionContext),
		Items:   items,
	}, versions, nil
}

func (c *cacheImpl) updateResourceEntries(typeURL typeurl.Index, resources map[string]resourceEntry, changed set.Set[string], previous cache.Resources, previousVersions map[string]string, versionContext string) (cache.Resources, map[string]string, error) {
	items := previous.Items
	versions := previousVersions
	cloned := false
	clone := func() {
		if cloned {
			return
		}
		items = maps.Clone(items)
		versions = maps.Clone(versions)
		cloned = true
	}

	for name := range changed.Members() {
		resource := resources[name].resource
		previousItem, resourceExists := items[name]
		previousVersion, versionExists := versions[name]
		if resource == nil {
			if !resourceExists && !versionExists {
				continue
			}
			clone()
			delete(items, name)
			delete(versions, name)
			continue
		}
		if resourceExists && versionExists &&
			previousItem.Resource == resource {
			continue
		}

		version, err := resourceContentVersion(resource)
		if err != nil {
			return cache.Resources{}, nil, err
		}
		// The content version is required for a changed resource. Reuse it for
		// semantic equality instead of performing another semantic comparison
		// immediately before marshaling the same protobuf. Equal versions retain
		// the published pointer and preserve the A-B-A no-op path.
		if resourceExists && versionExists && previousVersion == version {
			continue
		}
		clone()
		if items == nil {
			items = make(map[string]cache_types.ResourceWithTTL)
		}
		if versions == nil {
			versions = make(map[string]string)
		}
		items[name] = cache_types.ResourceWithTTL{Resource: resource}
		versions[name] = version
	}

	version := c.resourceVersion(typeURL, versions, versionContext)
	if !cloned && version == previous.Version {
		return previous, previousVersions, nil
	}
	return cache.Resources{Version: version, Items: items}, versions, nil
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

// desiredEndpoint normalizes endpoints by skipping 'name' if a cluster with that name does not exist, and returning an empty one if a cluster
func (resources *cacheResources) desiredEndpoint(name string) (*envoy_config_endpoint.ClusterLoadAssignment, bool) {
	if resource, exists := currentResource(resources[typeurl.Endpoint].entries, name); exists {
		// Skip wildcard :* endpoints that have no matching cluster,
		// as they cause snapshot inconsistency (EDS count > CDS references).
		// These are generated for backward compatibility with the old per-type
		// xDS caches but are not needed in the ADS snapshot.
		if _, hasCluster := currentResource(resources[typeurl.Cluster].entries, name); !hasCluster && strings.HasSuffix(name, ":*") {
			return nil, false
		}
		return typedResource[*envoy_config_endpoint.ClusterLoadAssignment](resource), true
	}
	for clusterName, entry := range resources[typeurl.Cluster].entries {
		if entry.resource != nil && clusterEndpointName(clusterName, typedResource[*envoy_config_cluster.Cluster](entry.resource)) == name {
			return &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}, true
		}
	}
	return nil, false
}

func (resources *cacheResources) endpointResourceNames() map[string]struct{} {
	names := make(map[string]struct{}, len(resources[typeurl.Endpoint].entries)+len(resources[typeurl.Cluster].entries))
	for name := range resources[typeurl.Endpoint].entries {
		names[name] = struct{}{}
	}
	for name, entry := range resources[typeurl.Cluster].entries {
		if entry.resource == nil {
			continue
		}
		cluster := typedResource[*envoy_config_cluster.Cluster](entry.resource)
		if endpointName := clusterEndpointName(name, cluster); endpointName != "" {
			names[endpointName] = struct{}{}
		}
	}
	return names
}

func (state *nodeState) changedEndpointResourceNames(previous *ciliumSnapshot) set.Set[string] {
	if state.resources[typeurl.Cluster].changed.Empty() {
		return state.resources[typeurl.Endpoint].changed
	}
	names := state.resources[typeurl.Endpoint].changed.Clone()
	previousClusters := previous[typeurl.Cluster].resources.Items
	for name := range state.resources[typeurl.Cluster].changed.Members() {
		names.Insert(name)
		if item, exists := previousClusters[name]; exists {
			cluster, ok := item.Resource.(*envoy_config_cluster.Cluster)
			if ok {
				if oldName := clusterEndpointName(name, cluster); oldName != "" {
					names.Insert(oldName)
				}
			}
		}
		if entry := state.resources[typeurl.Cluster].entries[name]; entry.resource != nil {
			cluster := typedResource[*envoy_config_cluster.Cluster](entry.resource)
			if newName := clusterEndpointName(name, cluster); newName != "" {
				names.Insert(newName)
			}
		}
	}
	return names
}

func (c *cacheImpl) resourceGroupFromLookup(typeURL typeurl.Index, names map[string]struct{}, lookup func(string) (cache_types.Resource, bool), versionContext string) (cache.Resources, map[string]string, error) {
	items := make(map[string]cache_types.ResourceWithTTL, len(names))
	versions := make(map[string]string, len(names))
	for name := range names {
		resource, exists := lookup(name)
		if !exists {
			continue
		}
		version, err := resourceContentVersion(resource)
		if err != nil {
			return cache.Resources{}, nil, err
		}
		items[name] = cache_types.ResourceWithTTL{Resource: resource}
		versions[name] = version
	}
	if len(items) == 0 {
		items = nil
	}
	if len(versions) == 0 {
		versions = nil
	}
	return cache.Resources{Version: c.resourceVersion(typeURL, versions, versionContext), Items: items}, versions, nil
}

func (c *cacheImpl) updateResourceLookup(typeURL typeurl.Index, changed set.Set[string], lookup func(string) (cache_types.Resource, bool), previous cache.Resources, previousVersions map[string]string, versionContext string) (cache.Resources, map[string]string, error) {
	items := previous.Items
	versions := previousVersions
	cloned := false
	clone := func() {
		if cloned {
			return
		}
		items = maps.Clone(items)
		versions = maps.Clone(versions)
		cloned = true
	}
	for name := range changed.Members() {
		resource, exists := lookup(name)
		previousItem, resourceExists := items[name]
		previousVersion, versionExists := versions[name]
		if !exists {
			if !resourceExists && !versionExists {
				continue
			}
			clone()
			delete(items, name)
			delete(versions, name)
			continue
		}
		if resourceExists && versionExists &&
			previousItem.Resource == resource {
			continue
		}
		version, err := resourceContentVersion(resource)
		if err != nil {
			return cache.Resources{}, nil, err
		}
		if resourceExists && versionExists && previousVersion == version {
			continue
		}
		clone()
		if items == nil {
			items = make(map[string]cache_types.ResourceWithTTL)
		}
		if versions == nil {
			versions = make(map[string]string)
		}
		items[name] = cache_types.ResourceWithTTL{Resource: resource}
		versions[name] = version
	}
	version := c.resourceVersion(typeURL, versions, versionContext)
	if !cloned && version == previous.Version {
		return previous, previousVersions, nil
	}
	return cache.Resources{Version: version, Items: items}, versions, nil
}

func (c *cacheImpl) generateSnapshotFromState(state *nodeState) (cache.ResourceSnapshot, error) {
	view := cacheSnapshotResourceView{resources: &state.resources}
	var resourceGroups typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Indices() {
		context := snapshotVersionContext(view, typeURL)
		var group cache.Resources
		var versions map[string]string
		var err error
		if typeURL == typeurl.Endpoint {
			group, versions, err = c.resourceGroupFromLookup(typeURL, state.resources.endpointResourceNames(), func(name string) (cache_types.Resource, bool) {
				return state.resources.desiredEndpoint(name)
			}, context)
		} else {
			group, versions, err = c.resourceGroupFromEntries(typeURL, state.resources[typeURL].entries, context)
		}
		if err != nil {
			return nil, err
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources: group,
			versions:  versions,
		}
	}
	return newCiliumSnapshot(resourceGroups), nil
}

func (c *cacheImpl) generateSnapshotFromStateIncrementally(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error) {
	previousSnapshot, regenerate, ok := c.canGenerateSnapshotIncrementally(previous, changedTypeURLs)
	if !ok {
		return c.generateSnapshotFromState(state)
	}
	if regenerate.Empty() {
		return previousSnapshot, nil
	}

	view := cacheSnapshotResourceView{resources: &state.resources}
	resourceGroups := typeurl.Slots[snapshotResourceGroup](*previousSnapshot)
	for typeURL := range regenerate.Members() {
		context := snapshotVersionContext(view, typeURL)
		previousGroup := previousSnapshot[typeURL]
		var group cache.Resources
		var versions map[string]string
		var err error
		if typeURL == typeurl.Endpoint {
			group, versions, err = c.updateResourceLookup(typeURL, state.changedEndpointResourceNames(previousSnapshot), func(name string) (cache_types.Resource, bool) {
				return state.resources.desiredEndpoint(name)
			}, previousGroup.resources, previousGroup.versions, context)
		} else {
			typeState := &state.resources[typeURL]
			group, versions, err = c.updateResourceEntries(typeURL, typeState.entries, typeState.changed, previousGroup.resources, previousGroup.versions, context)
		}
		if err != nil {
			return nil, err
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources: group,
			versions:  versions,
		}
	}
	return newCiliumSnapshot(resourceGroups), nil
}

func (c *cacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return c.completionCbs
}

type immediateCompletion struct {
	comp                      *completion.Completion
	typeURL                   typeurl.Index
	generation                uint64
	err                       error
	completeUnsentCompletions bool
	completeUnsentWaitersOnly bool
}

// generationWait describes one ACK/NACK wait. generation identifies either the
// last mutation of the matching resource or the staged/published snapshot which
// currently represents its TypeURL.
type generationWait struct {
	callback   func(error)
	generation uint64
}

type typeURLWaits = typeurl.Map[generationWait]

// resourceTransaction owns one atomic cache mutation. The cache, context and
// node are fixed when the transaction starts, while response delivery and
// completion work is accumulated for execution after mutex is released.
type resourceTransaction struct {
	cache  *cacheImpl
	ctx    context.Context
	nodeID string

	// state is looked up once while acquiring the cache lock. Transactions
	// update it when they create or discard node state, so subsequent mutation
	// steps do not repeatedly hash nodeID.
	state *nodeState

	generation              uint64
	deliveries              []responseDelivery
	finalized               []finalizedCompletion
	registeredCompletions   set.Set[*completion.Completion]
	immediateCompletions    []immediateCompletion
	listenerChanges         []ListenerChange
	networkPolicyStateEmpty bool
	updateFailed            bool
	acceptedCallback        func(error)   // single callback common case
	acceptedCallbacks       []func(error) // additional callbacks
}

func (c *cacheImpl) beginResourceTransaction(ctx context.Context, nodeID string) resourceTransaction {
	c.mutex.Lock()
	return resourceTransaction{
		cache:  c,
		ctx:    ctx,
		nodeID: nodeID,
		state:  c.nodeStates[nodeID],
	}
}

func (tx *resourceTransaction) currentResourceGeneration() uint64 {
	if tx.state == nil {
		return 0
	}
	return tx.state.resourceGeneration
}

// addAcceptedCallback defers an already-satisfied callback until after the
// cache mutex is released. No Completion needs to be added to wg because there
// is no asynchronous work for it to wait on.
func (tx *resourceTransaction) addAcceptedCallback(wg *completion.WaitGroup, callback func(error)) {
	if wg == nil || callback == nil {
		return
	}
	if tx.acceptedCallback == nil {
		tx.acceptedCallback = callback
		return
	}
	tx.acceptedCallbacks = append(tx.acceptedCallbacks, callback)
}

func (tx *resourceTransaction) complete() {
	c := tx.cache
	var noListenerWaiters callbacks.DetachedWaiters
	if !tx.updateFailed && tx.state != nil && len(tx.listenerChanges) > 0 &&
		c.listenerObserver != nil && c.listenerObserver.ApplyCommittedChanges(tx.nodeID, tx.listenerChanges) {
		// Detach while holding the cache lock. A new policy update can
		// register a wait after a listener is re-added, even if its
		// resource generation predates this removal.
		noListenerWaiters = c.completionCbs.TakePendingWaiters(tx.nodeID, typeurl.NetworkPolicy)
	}
	c.mutex.Unlock()
	c.deliverResponses(tx.deliveries)
	if tx.updateFailed {
		for comp := range tx.registeredCompletions.Members() {
			c.completionCbs.RemoveTypeGenerationCompletion(comp)
		}
		return
	}
	c.completeFinalized(tx.nodeID, tx.finalized)
	if tx.networkPolicyStateEmpty {
		// With no NPDS resources there may be no policy watch or ACK to resolve
		// older policy waiters. The empty state is still retained for lazy
		// publication if Envoy connects later.
		c.completionCbs.CompleteWaitersThroughGeneration(
			tx.nodeID, typeurl.NetworkPolicy, tx.generation, nil)
	}
	c.completeImmediateCompletions(tx.nodeID, tx.immediateCompletions)
	noListenerWaiters.Complete(nil)
	if tx.acceptedCallback != nil {
		tx.acceptedCallback(nil)
		for _, callback := range tx.acceptedCallbacks {
			callback(nil)
		}
	}
}

func (c *cacheImpl) registerGenerationCompletions(nodeID string, newSnapshot, oldSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, waits typeURLWaits, revertFunc RevertGenerationFunc) (set.Set[*completion.Completion], []immediateCompletion) {
	var completions set.Set[*completion.Completion]
	// Do not preallocate: immediate completions are uncommon, and reserving
	// capacity here adds an allocation to every resource update.
	var immediateCompletions []immediateCompletion
	if wg != nil && !waits.Empty() {
		for typeURL, wait := range waits.All() {
			owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, wait.generation)
			comp := wg.AddCompletionWithCallback(owner, wait.callback)
			if typeURL == typeurl.NetworkPolicy && len(newSnapshot.GetResourcesAndTTL(NetworkPolicyTypeURL)) == 0 {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					generation:                wait.generation,
					completeUnsentWaitersOnly: true,
				})
				continue
			}
			version := newSnapshot.GetVersion(typeURL.URL())
			versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL.URL()) != version
			registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, version, versionChanged, revertFunc)
			if !registered {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					generation:                wait.generation,
					err:                       err,
					completeUnsentCompletions: err == nil,
				})
				continue
			}
			completions.Insert(comp)
		}
	}
	return completions, immediateCompletions
}

func (c *cacheImpl) registerStagedGenerationCompletions(nodeID string, networkPoliciesEmpty bool, wg *completion.WaitGroup, waits typeURLWaits, revertFunc RevertGenerationFunc) (set.Set[*completion.Completion], []immediateCompletion) {
	var completions set.Set[*completion.Completion]
	// Do not preallocate: immediate completions are uncommon, and reserving
	// capacity here adds an allocation to every resource update.
	var immediateCompletions []immediateCompletion
	if wg == nil || waits.Empty() {
		return completions, immediateCompletions
	}

	for typeURL, wait := range waits.All() {
		owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, wait.generation)
		comp := wg.AddCompletionWithCallback(owner, wait.callback)
		if typeURL == typeurl.NetworkPolicy && networkPoliciesEmpty {
			immediateCompletions = append(immediateCompletions, immediateCompletion{
				comp:                      comp,
				typeURL:                   typeURL,
				generation:                wait.generation,
				completeUnsentWaitersOnly: true,
			})
			continue
		}
		registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, "", true, revertFunc)
		if !registered {
			immediateCompletions = append(immediateCompletions, immediateCompletion{
				comp:                      comp,
				typeURL:                   typeURL,
				generation:                wait.generation,
				err:                       err,
				completeUnsentCompletions: err == nil,
			})
			continue
		}
		completions.Insert(comp)
	}
	return completions, immediateCompletions
}

type finalizedCompletion struct {
	typeURL    typeurl.Index
	generation uint64
	err        error
}

func (c *cacheImpl) completeImmediateCompletions(nodeID string, immediateCompletions []immediateCompletion) {
	for _, immediate := range immediateCompletions {
		if immediate.completeUnsentWaitersOnly {
			c.completionCbs.CompleteWaitersThroughGeneration(nodeID, immediate.typeURL, immediate.generation, nil)
		} else if immediate.completeUnsentCompletions {
			c.completionCbs.CompleteCompletionsThroughGeneration(nodeID, immediate.typeURL, immediate.generation, nil)
		}
		immediate.comp.Complete(immediate.err)
	}
}

func snapshotTypesChangedBy(changedTypeURLs typeurl.Set) typeurl.Set {
	regenerate, ok := incrementalSnapshotTypeURLs(changedTypeURLs)
	if ok {
		return regenerate
	}
	return typeurl.All()
}

func mergeTypeURLWaits(base typeurl.Set, additions typeURLWaits) typeurl.Set {
	for typeURL := range additions.Keys() {
		base.Insert(typeURL)
	}
	return base
}

// strictADSConsistencyCompanion returns the other resource type that must be
// rolled back together with typeURL to preserve go-control-plane snapshot
// consistency. Strict ADS requires the EDS resources referenced by CDS and the
// RDS resources referenced by LDS to match exactly.
func strictADSConsistencyCompanion(typeURL typeurl.Index) (typeurl.Index, bool) {
	switch typeURL {
	case typeurl.Listener:
		return typeurl.Route, true
	case typeurl.Route:
		return typeurl.Listener, true
	case typeurl.Cluster:
		return typeurl.Endpoint, true
	case typeurl.Endpoint:
		return typeurl.Cluster, true
	default:
		return typeurl.Count, false
	}
}

func (state *nodeState) mergeStagedRollbacks(base typeurl.Map[rollbackResources], typeURLs typeurl.Set, inverse inverseResources, generation uint64, strictADS bool) typeurl.Map[rollbackResources] {
	if typeURLs.Empty() {
		return base
	}
	for typeURL := range typeURLs.Members() {
		rollback, _ := base.Get(typeURL)
		rollback = rollback.mergeTypeURL(state, typeURL, inverse, generation)
		if strictADS {
			if companion, ok := strictADSConsistencyCompanion(typeURL); ok {
				rollback = rollback.mergeTypeURL(state, companion, inverse, generation)
			}
		}
		base.Set(typeURL, rollback)
	}
	return base
}

// cloneRollbackResources copies the one map owned by a staged rollback
// slot. Other fields are empty because rollback state is partitioned by
// TypeURL before it is staged.
func cloneRollbackResources(typeURL typeurl.Index, rollback rollbackResources) rollbackResources {
	rollback[typeURL] = maps.Clone(rollback[typeURL])
	return rollback
}

func cloneStagedRollbacks(rollbacks typeurl.Map[rollbackResources]) typeurl.Map[rollbackResources] {
	var cloned typeurl.Map[rollbackResources]
	for typeURL, rollback := range rollbacks.All() {
		cloned.Set(typeURL, cloneRollbackResources(typeURL, rollback))
	}
	return cloned
}

func (state *nodeState) acquireRollbackSet(rollbacks typeurl.Map[rollbackResources]) {
	for _, rollback := range rollbacks.All() {
		state.updateRollbackOwners(rollback, 1)
	}
}

func (state *nodeState) releaseRollbackSet(rollbacks typeurl.Map[rollbackResources]) {
	for _, rollback := range rollbacks.All() {
		state.releaseRollback(rollback)
	}
}

// finalizeStagedSnapshotLocked constructs and installs the newest staged
// snapshot for nodeID. The caller must hold c.mutex. Completion resolution is
// returned to the caller so callbacks can run after the cache lock is released.
func (c *cacheImpl) finalizeStagedSnapshotLocked(ctx context.Context, nodeID string) (bool, []finalizedCompletion, error) {
	state := c.nodeStates[nodeID]
	if state == nil || state.staged == nil {
		return false, nil, nil
	}
	staged := state.staged
	if staged.generator == nil {
		return false, nil, fmt.Errorf("missing snapshot generator for node %s", nodeID)
	}

	oldSnapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	newSnapshot, err := staged.generator(state, oldSnapshot, staged.changedTypeURLs)
	if err != nil {
		return false, nil, err
	}

	oldGeneration := state.snapshotGeneration
	// Stage the authoritative finalized generation before SetSnapshot.
	// go-control-plane may synchronously build a response while SetSnapshot is
	// running, while CreateWatch responses use context.Background.
	c.completionCbs.SetPublishedSnapshot(nodeID, staged.generation, newSnapshot)
	err = c.SnapshotCache.SetSnapshot(callbacks.WithSnapshotGeneration(ctx, staged.generation), nodeID, newSnapshot)
	if err != nil {
		// SnapshotCache stores the snapshot before delivering watch responses. A
		// canceled delivery may therefore return an error after publication has
		// committed; keep generation state in that case.
		currentSnapshot, getErr := c.SnapshotCache.GetSnapshot(nodeID)
		committed := getErr == nil && !c.areDifferentSnapshots(currentSnapshot, newSnapshot)
		if !committed {
			c.completionCbs.SetPublishedSnapshot(nodeID, oldGeneration, oldSnapshot)
			return false, nil, err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}

	state.staged = nil
	state.snapshotGeneration = staged.generation
	for typeURL := range typeurl.Indices() {
		state.resources[typeURL].changed = set.Set[string]{}
	}
	// Retain rollback only for resource types whose published version changed.
	// Until go-control-plane actually produces a response, repeated published
	// generations are coalesced into one rollback per type. An older mutation
	// without a WaitGroup may precede a tracked mutation in the same eventual
	// response, and a NACK must restore the state before that whole batch.
	for typeURL, rollback := range staged.rollbacks.All() {
		versionChanged := oldSnapshot == nil ||
			oldSnapshot.GetVersion(typeURL.URL()) != newSnapshot.GetVersion(typeURL.URL())
		if !versionChanged {
			state.releaseRollback(rollback)
			continue
		}
		c.retainUnsentRollbackLocked(nodeID, typeURL, staged.generation, rollback)
	}
	finalized := make([]finalizedCompletion, 0, staged.completionTypeURLs.Len())
	for typeURL := range staged.completionTypeURLs.Members() {
		version := newSnapshot.GetVersion(typeURL.URL())
		versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL.URL()) != version
		complete, completeErr := c.completionCbs.FinalizeTypeGeneration(
			nodeID, typeURL, staged.generation, version, versionChanged)
		if complete {
			finalized = append(finalized, finalizedCompletion{
				typeURL:    typeURL,
				generation: staged.generation,
				err:        completeErr,
			})
		}
	}
	return true, finalized, nil
}

func (c *cacheImpl) completeFinalized(nodeID string, finalized []finalizedCompletion) {
	for _, result := range finalized {
		c.completionCbs.CompleteCompletionsThroughGeneration(
			nodeID, result.typeURL, result.generation, result.err)
	}
}

func resourceValue[V interface {
	proto.Message
	comparable
}](resource V) cache_types.Resource {
	var zero V
	if resource == zero {
		return nil
	}
	return resource
}

func typedResource[V proto.Message](resource cache_types.Resource) V {
	if resource == nil {
		var zero V
		return zero
	}
	return resource.(V)
}

func currentResource(resources map[string]resourceEntry, name string) (cache_types.Resource, bool) {
	resource := resources[name].resource
	return resource, resource != nil
}

func prepareResourceMap[V interface {
	proto.Message
	comparable
}](changes *resourceChanges, typeURL typeurl.Index, current map[string]resourceEntry, removed, upserted map[string]V) {
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		old := current[name]
		if old.resource != nil {
			changes.add(typeURL, name, old, nil)
		}
	}
	for name, resource := range upserted {
		old := current[name]
		desired := resourceValue(resource)
		if old.resource == desired ||
			(old.resource != nil && desired != nil && xds.ResourceEqual(old.resource, desired)) {
			continue
		}
		changes.add(typeURL, name, old, desired)
	}
}

func (state *nodeState) prepareResourceMutation(mutations ResourceMutations) (resourceChanges, typeurl.Set, inverseResources) {
	removeSet := mutations.Removed
	upsertSet := mutations.Upserted
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.Listener, state.resourceEntries(typeurl.Listener), removeSet.Listeners, upsertSet.Listeners)
	prepareResourceMap(&changes, typeurl.Route, state.resourceEntries(typeurl.Route), removeSet.Routes, upsertSet.Routes)
	prepareResourceMap(&changes, typeurl.Cluster, state.resourceEntries(typeurl.Cluster), removeSet.Clusters, upsertSet.Clusters)
	prepareResourceMap(&changes, typeurl.Endpoint, state.resourceEntries(typeurl.Endpoint), removeSet.Endpoints, upsertSet.Endpoints)
	prepareResourceMap(&changes, typeurl.Secret, state.resourceEntries(typeurl.Secret), removeSet.Secrets, upsertSet.Secrets)
	return changes, changes.typeURLs(), changes.inverse()
}

func mergeRollbackMap(state *nodeState, typeURL typeurl.Index, current map[string]rollbackEntry, desired map[string]resourceEntry, inverse inverseResources, generation uint64) map[string]rollbackEntry {
	if inverse.len(typeURL) == 0 {
		return current
	}
	if current == nil {
		current = make(map[string]rollbackEntry, inverse.len(typeURL))
	}
	merge := func(name string, previous resourceEntry) {
		entry, exists := current[name]
		if !exists {
			entry.previous = previous
		}
		if desired[name].resource == nil {
			state.addRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: generation})
		}
		if exists {
			state.removeRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: entry.expectedGeneration})
		}
		entry.expectedGeneration = generation
		current[name] = entry
	}
	for name, previous := range inverse.resources(typeURL) {
		merge(name, previous)
	}
	return current
}

func (rollback rollbackResources) mergeTypeURL(state *nodeState, typeURL typeurl.Index, inverse inverseResources, generation uint64) rollbackResources {
	rollback[typeURL] = mergeRollbackMap(state, typeURL, rollback[typeURL], state.resources[typeURL].entries, inverse, generation)
	return rollback
}

// mergeRollbackHistoryMap folds a newer, independently owned rollback into an
// older unsent one. The oldest previous value remains the rollback target,
// while the newest expected generation fences the combined rollback. Ownership
// of a superseded tombstone moves to the newer entry.
func mergeRollbackHistoryMap(state *nodeState, typeURL typeurl.Index, older, newer map[string]rollbackEntry) map[string]rollbackEntry {
	if len(newer) == 0 {
		return older
	}
	if older == nil {
		return newer
	}
	for name, newerEntry := range newer {
		if olderEntry, exists := older[name]; exists {
			state.removeRollbackOwner(typeURL, rollbackOwnerKey{
				name:       name,
				generation: olderEntry.expectedGeneration,
			})
			newerEntry.previous = olderEntry.previous
		}
		older[name] = newerEntry
	}
	return older
}

func (rollback rollbackResources) mergeHistory(state *nodeState, newer rollbackResources) rollbackResources {
	for typeURL := range typeurl.Indices() {
		rollback[typeURL] = mergeRollbackHistoryMap(state, typeURL, rollback[typeURL], newer[typeURL])
	}
	return rollback
}

func (state *nodeState) resourceRevert(rollback rollbackResources) (resourceChanges, resourceEntrySlots) {
	if state == nil {
		return resourceChanges{}, resourceEntrySlots{}
	}
	var changes resourceChanges
	var restored resourceEntrySlots
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		for name, entry := range rollback[typeURL] {
			previous := current[name]
			if previous.generation != entry.expectedGeneration ||
				(previous.resource == entry.previous.resource ||
					(previous.resource != nil && entry.previous.resource != nil && xds.ResourceEqual(previous.resource, entry.previous.resource))) {
				continue
			}
			changes.add(typeURL, name, previous, entry.previous.resource)
			if restored[typeURL] == nil {
				restored[typeURL] = make(map[string]resourceEntry)
			}
			restored[typeURL][name] = entry.previous
		}
	}
	return changes, restored
}

func (state *nodeState) resourceRevertInverse(generation uint64, inverse inverseResources) (resourceChanges, resourceEntrySlots) {
	if state == nil {
		return resourceChanges{}, resourceEntrySlots{}
	}
	var changes resourceChanges
	var restored resourceEntrySlots
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		for name, previous := range inverse.resources(typeURL) {
			entry := current[name]
			// The inverse only contains semantic changes made by generation.
			// A matching generation therefore cannot already contain previous.
			if entry.generation != generation {
				continue
			}
			changes.add(typeURL, name, entry, previous.resource)
			if restored[typeURL] == nil {
				restored[typeURL] = make(map[string]resourceEntry)
			}
			restored[typeURL][name] = previous
		}
	}
	return changes, restored
}

func updateRollbackOwnerMap(state *nodeState, typeURL typeurl.Index, resources map[string]rollbackEntry, delta int) {
	if len(resources) == 0 {
		return
	}
	for name, entry := range resources {
		key := rollbackOwnerKey{name: name, generation: entry.expectedGeneration}
		if delta > 0 {
			state.addRollbackOwner(typeURL, key)
			continue
		}
		state.removeRollbackOwner(typeURL, key)
	}
}

func (state *nodeState) updateRollbackOwners(rollback rollbackResources, delta int) {
	for typeURL := range typeurl.Indices() {
		updateRollbackOwnerMap(state, typeURL, rollback[typeURL], delta)
	}
}

func (state *nodeState) updateInverseRollbackOwnerMap(typeURL typeurl.Index, desired map[string]resourceEntry, inverse inverseResources, generation uint64, delta int) {
	update := func(name string) {
		key := rollbackOwnerKey{name: name, generation: generation}
		if delta > 0 {
			if desired[name].resource == nil {
				state.addRollbackOwner(typeURL, key)
			}
		} else {
			state.removeRollbackOwner(typeURL, key)
		}
	}
	for name := range inverse.resources(typeURL) {
		update(name)
	}
}

func (state *nodeState) updateInverseRollbackOwners(inverse inverseResources, generation uint64, delta int) {
	for typeURL := range typeurl.Indices() {
		state.updateInverseRollbackOwnerMap(typeURL, state.resources[typeURL].entries, inverse, generation, delta)
	}
}

func pruneReleasedTombstones(state *nodeState, typeURL typeurl.Index, resources *map[string]resourceEntry, rollback map[string]rollbackEntry) {
	for name, rollbackEntry := range rollback {
		entry := (*resources)[name]
		if entry.resource != nil || entry.generation != rollbackEntry.expectedGeneration {
			continue
		}
		key := rollbackOwnerKey{name: name, generation: entry.generation}
		if state.rollbackOwnerCount(typeURL, key) == 0 {
			delete(*resources, name)
		}
	}
	if len(*resources) == 0 {
		*resources = nil
	}
}

func (state *nodeState) releaseRollback(rollback rollbackResources) {
	state.updateRollbackOwners(rollback, -1)
	for typeURL := range typeurl.Indices() {
		pruneReleasedTombstones(state, typeURL, &state.resources[typeURL].entries, rollback[typeURL])
	}
}

func (state *nodeState) pruneInverseTombstones(typeURL typeurl.Index, resources *map[string]resourceEntry, inverse inverseResources, generation uint64) {
	prune := func(name string) {
		entry := (*resources)[name]
		if entry.resource != nil || entry.generation != generation {
			return
		}
		key := rollbackOwnerKey{name: name, generation: generation}
		if state.rollbackOwnerCount(typeURL, key) == 0 {
			delete(*resources, name)
		}
	}
	for name := range inverse.resources(typeURL) {
		prune(name)
	}
	if len(*resources) == 0 {
		*resources = nil
	}
}

func (state *nodeState) releaseInverseRollback(inverse inverseResources, generation uint64) {
	state.updateInverseRollbackOwners(inverse, generation, -1)
	for typeURL := range typeurl.Indices() {
		state.pruneInverseTombstones(typeURL, &state.resources[typeURL].entries, inverse, generation)
	}
}

func (state *resourceTypeState) commitEntries(entries map[string]resourceEntry) {
	for name, entry := range entries {
		state.commitEntry(name, entry)
	}
}

func (state *resourceTypeState) commitEntry(name string, entry resourceEntry) {
	if entry.resource == nil && entry.generation == 0 {
		delete(state.entries, name)
	} else {
		if state.entries == nil {
			state.entries = make(map[string]resourceEntry)
		}
		state.entries[name] = entry
	}
	state.changed.Insert(name)
}

func (state *nodeState) commitResourceMutation(changes resourceChanges, generation uint64, restored *resourceEntrySlots) {
	commit := func(change resourceChange) {
		entry := resourceEntry{resource: change.resource, generation: generation}
		if restored != nil {
			if previous, exists := (*restored)[change.typeURL][change.name]; exists {
				entry = previous
			}
		}
		state.resources[change.typeURL].commitEntry(change.name, entry)
	}
	if !changes.empty() {
		commit(changes.first)
	}
	for _, change := range changes.more {
		commit(change)
	}
}

func committedListenerChanges(changes resourceChanges) []ListenerChange {
	var listenerChanges []ListenerChange
	add := func(change resourceChange) {
		if change.typeURL == typeurl.Listener {
			listenerChanges = append(listenerChanges, ListenerChange{
				Previous: typedResource[*envoy_config_listener.Listener](change.previous.resource),
				Current:  typedResource[*envoy_config_listener.Listener](change.resource),
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

func (state *nodeState) restoreResourceEntries(entries resourceEntrySlots) {
	for typeURL := range typeurl.Indices() {
		state.resources[typeURL].commitEntries(entries[typeURL])
	}
}

func (state *resourceTypeState) reconcileChangedNames(affected map[string]resourceEntry, published map[string]cache_types.ResourceWithTTL) {
	for name := range affected {
		resource := state.entries[name].resource
		publishedResource, publishedExists := published[name]
		if resource == nil {
			if !publishedExists {
				state.changed.Remove(name)
			}
			continue
		}
		if publishedExists &&
			(publishedResource.Resource == resource || xds.ResourceEqual(publishedResource.Resource, resource)) {
			state.changed.Remove(name)
		}
	}
}

func (state *nodeState) reconcileChangedResourceNames(affected resourceEntrySlots, published cache.ResourceSnapshot) {
	resources := func(typeURL typeurl.Index) map[string]cache_types.ResourceWithTTL {
		if published == nil {
			return nil
		}
		return published.GetResourcesAndTTL(typeURL.URL())
	}
	for typeURL := range typeurl.Indices() {
		state.resources[typeURL].reconcileChangedNames(affected[typeURL], resources(typeURL))
	}
}

func resourceEntriesEmpty(resources map[string]resourceEntry) bool {
	for _, entry := range resources {
		if entry.resource != nil {
			return false
		}
	}
	return true
}

func (state *nodeState) networkPoliciesEmpty() bool {
	if state == nil {
		return true
	}
	return resourceEntriesEmpty(state.resources[typeurl.NetworkPolicy].entries)
}

func validateResourceName(typeURL typeurl.Index, name string) error {
	if name == "" {
		return fmt.Errorf("%s resource name must not be empty", typeURL.URL())
	}
	return nil
}

func validateResourceMapNames[V any](typeURL typeurl.Index, removed, upserted map[string]V) error {
	if _, exists := removed[""]; exists {
		return validateResourceName(typeURL, "")
	}
	if _, exists := upserted[""]; exists {
		return validateResourceName(typeURL, "")
	}
	return nil
}

func validateResourceMutations(mutations ResourceMutations) error {
	removed, upserted := mutations.Removed, mutations.Upserted
	if err := validateResourceMapNames(typeurl.Listener, removed.Listeners, upserted.Listeners); err != nil {
		return err
	}
	if err := validateResourceMapNames(typeurl.Route, removed.Routes, upserted.Routes); err != nil {
		return err
	}
	if err := validateResourceMapNames(typeurl.Cluster, removed.Clusters, upserted.Clusters); err != nil {
		return err
	}
	if err := validateResourceMapNames(typeurl.Endpoint, removed.Endpoints, upserted.Endpoints); err != nil {
		return err
	}
	if err := validateResourceMapNames(typeurl.Secret, removed.Secrets, upserted.Secrets); err != nil {
		return err
	}
	return nil
}

// ApplyResources applies sparse removals and upserts to the cache-private
// desired state. It is the authority for semantic no-op detection, changed
// resource names and generation-fenced reverts. Published maps remain immutable
// and are updated copy-on-write only when the staged snapshot is finalized.
func (c *cacheImpl) ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (bool, Rollback, error) {
	if err := validateResourceMutations(mutations); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, rollback, err := tx.applyResourcesLocked(mutations, wg, updatedTypeURLs, nil)
	tx.complete()
	return updated, rollback, err
}

func prepareSingleResource[V interface {
	proto.Message
	comparable
}](current map[string]resourceEntry, name string, resource V) (previous resourceEntry, desired V, desiredExists, changed bool) {
	previous = current[name]
	var zero V
	if resource == zero {
		return previous, zero, false, previous.resource != nil
	}
	if previous.resource != nil && (previous.resource == resource || xds.ResourceEqual(previous.resource, resource)) {
		return previous, previous.resource.(V), true, false
	}
	return previous, resource, true, true
}

// finishUnchangedSingleResourceLocked attaches a no-op update directly to the
// resource's current ACK state without constructing a broad ResourceMutations
// value or inspecting unrelated resource types. Caller must hold mutex.
func (tx *resourceTransaction) finishUnchangedSingleResourceLocked(typeURL typeurl.Index, name string, generation uint64, desired proto.Message, desiredExists bool, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	if wg == nil {
		return false, nil, nil
	}
	if tx.cache.completionCbs.ResourceAccepted(tx.nodeID, typeURL, name, desired, desiredExists) {
		tx.addAcceptedCallback(wg, callback)
		return false, nil, nil
	}
	var waits typeURLWaits
	waits.Set(typeURL, generationWait{callback: callback, generation: generation})
	return false, nil, tx.awaitCurrentVersionLocked(wg, waits)
}

// applyChangedSingleResourceLocked sends an already-prepared typed mutation
// through the shared generation, revert, and lazy-publication machinery. It
// handles completion state directly because the affected resource and TypeURL
// are already known. Caller must hold mutex.
func (tx *resourceTransaction) applyChangedSingleResourceLocked(typeURL typeurl.Index, name string, desired proto.Message, desiredExists bool, inverse inverseResources, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	c := tx.cache
	previous, _ := inverse.get(typeURL, name)
	var changes resourceChanges
	var next cache_types.Resource
	if desiredExists {
		next = desired
	}
	changes.add(typeURL, name, previous, next)
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	changedTypeURLs := typeurl.NewSet(typeURL)
	lifecycle := c.newCallerRollbackLifecycle(tx.ctx, tx.nodeID, tx.generation, inverse)
	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)

	accepted := false
	var changedWaits typeURLWaits
	if wg != nil {
		accepted = c.completionCbs.ChangedResourceAccepted(
			tx.nodeID, typeURL, name,
			previous.resource, previous.resource != nil,
			desired, desiredExists,
		)
		if !accepted {
			changedWaits.Set(typeURL, generationWait{callback: callback, generation: tx.generation})
		}
	}
	err := tx.updateResourceChangesLocked(changes, inverse, dirtyTypeURLs, changedTypeURLs, c.defaultGenerator, wg, changedWaits, lifecycle, nil)
	if err != nil {
		return false, nil, err
	}
	if accepted {
		tx.addAcceptedCallback(wg, callback)
	}
	return true, lifecycle, nil
}

func (tx *resourceTransaction) applyListenerLocked(name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	state := tx.state
	var current map[string]resourceEntry
	if state != nil {
		current = state.resources[typeurl.Listener].entries
	}
	previous, desired, desiredExists, changed := prepareSingleResource(current, name, resource)
	if !changed {
		if state == nil {
			// no change without state can only be a removal of a nonexisting listener,
			// complete immediately when the transaction is done.
			tx.addAcceptedCallback(wg, callback)
			return false, nil, nil
		}
		return tx.finishUnchangedSingleResourceLocked(typeurl.Listener, name, previous.generation, desired, desiredExists, wg, callback)
	}

	tx.listenerChanges = []ListenerChange{{
		Previous: typedResource[*envoy_config_listener.Listener](previous.resource),
		Current:  resource,
	}}
	inverse := singleInverseEntry(typeurl.Listener, name, previous)
	return tx.applyChangedSingleResourceLocked(typeurl.Listener, name, desired, desiredExists, inverse, wg, callback)
}

func (tx *resourceTransaction) applyNetworkPolicyLocked(name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	state := tx.state
	var current map[string]resourceEntry
	if state != nil {
		current = state.resources[typeurl.NetworkPolicy].entries
	}
	previous, desired, desiredExists, changed := prepareSingleResource(current, name, resource)
	if !changed {
		if state == nil {
			// no change without state can only be a removal of a nonexisting policy,
			// complete immediately when the transaction is done.
			tx.addAcceptedCallback(wg, callback)
			return false, nil, nil
		}
		return tx.finishUnchangedSingleResourceLocked(typeurl.NetworkPolicy, name, previous.generation, desired, desiredExists, wg, callback)
	}

	inverse := singleInverseEntry(typeurl.NetworkPolicy, name, previous)
	return tx.applyChangedSingleResourceLocked(typeurl.NetworkPolicy, name, desired, desiredExists, inverse, wg, callback)
}

func (tx *resourceTransaction) applyNetworkPolicyHostsLocked(name string, resource *cilium.NetworkPolicyHosts) (bool, Rollback, error) {
	state := tx.state
	var current map[string]resourceEntry
	if state != nil {
		current = state.resources[typeurl.NetworkPolicyHosts].entries
	}
	previous, desired, desiredExists, changed := prepareSingleResource(current, name, resource)
	if !changed {
		return false, nil, nil
	}

	inverse := singleInverseEntry(typeurl.NetworkPolicyHosts, name, previous)
	return tx.applyChangedSingleResourceLocked(typeurl.NetworkPolicyHosts, name, desired, desiredExists, inverse, nil, nil)
}

func (c *cacheImpl) UpsertListener(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	if err := validateResourceName(typeurl.Listener, name); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, rollback, err := tx.applyListenerLocked(name, resource, wg, callback)
	tx.complete()
	return updated, rollback, err
}

func (c *cacheImpl) RemoveListener(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	if err := validateResourceName(typeurl.Listener, name); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, rollback, err := tx.applyListenerLocked(name, nil, wg, callback)
	tx.complete()
	return updated, rollback, err
}

func (c *cacheImpl) UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	if err := validateResourceName(typeurl.NetworkPolicy, name); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	if wg != nil && c.listenerObserver != nil && !c.listenerObserver.HasNPDSListeners(nodeID) {
		tx.addAcceptedCallback(wg, callback)
		wg = nil
	}
	updated, rollback, err := tx.applyNetworkPolicyLocked(name, resource, wg, callback)
	tx.complete()
	return updated, rollback, err
}

func (c *cacheImpl) RemoveNetworkPolicy(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, Rollback, error) {
	if err := validateResourceName(typeurl.NetworkPolicy, name); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	if wg != nil && c.listenerObserver != nil && !c.listenerObserver.HasNPDSListeners(nodeID) {
		tx.addAcceptedCallback(wg, callback)
		wg = nil
	}
	updated, rollback, err := tx.applyNetworkPolicyLocked(name, nil, wg, callback)
	tx.complete()
	return updated, rollback, err
}

func (c *cacheImpl) RemoveAllNetworkPolicies(ctx context.Context, nodeID string) (bool, Rollback, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	state := tx.state
	if state == nil {
		tx.complete()
		return false, nil, nil
	}

	var changes resourceChanges
	for name, previous := range state.resources[typeurl.NetworkPolicy].entries {
		if previous.resource != nil {
			changes.add(typeurl.NetworkPolicy, name, previous, nil)
		}
	}
	if changes.empty() {
		tx.complete()
		return false, nil, nil
	}

	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	inverse := changes.inverse()
	lifecycle := c.newCallerRollbackLifecycle(ctx, nodeID, tx.generation, inverse)
	changedTypeURLs := typeurl.NewSet(typeurl.NetworkPolicy)
	err := tx.updateResourceChangesLocked(changes, inverse, snapshotTypesChangedBy(changedTypeURLs),
		changedTypeURLs, c.defaultGenerator, nil, typeURLWaits{}, lifecycle, nil)
	tx.complete()
	if err != nil {
		return false, nil, err
	}
	return true, lifecycle, nil
}

func (c *cacheImpl) UpsertNetworkPolicyHosts(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (bool, Rollback, error) {
	if err := validateResourceName(typeurl.NetworkPolicyHosts, name); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, rollback, err := tx.applyNetworkPolicyHostsLocked(name, resource)
	tx.complete()
	return updated, rollback, err
}

func (c *cacheImpl) RemoveNetworkPolicyHosts(ctx context.Context, nodeID, name string) (bool, Rollback, error) {
	if err := validateResourceName(typeurl.NetworkPolicyHosts, name); err != nil {
		return false, nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, rollback, err := tx.applyNetworkPolicyHostsLocked(name, nil)
	tx.complete()
	return updated, rollback, err
}

// applyResourcesLocked allocates generations and constructs generation-fenced
// reverts inside the cache. Caller must hold mutex.
func (tx *resourceTransaction) applyResourcesLocked(mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks, restoredEntries *resourceEntrySlots) (bool, Rollback, error) {
	c := tx.cache
	if !updatedTypeURLs.Known() && (len(mutations.Removed.Listeners) > 0 || len(mutations.Upserted.Listeners) > 0) {
		// Listener mutations are always ACK-tracked by the legacy server because
		// callers may immediately depend on the listener being usable. Infer that
		// contract from mutation intent, including semantic no-ops, so callers
		// cannot accidentally omit the AwaitCurrentVersion path.
		updatedTypeURLs.Set(typeurl.Listener, nil)
	}

	state := tx.state
	stateExists := state != nil
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(mutations)
	if !stateExists && changedTypeURLs.Empty() {
		for _, callback := range updatedTypeURLs.All() {
			tx.addAcceptedCallback(wg, callback)
		}
		return false, nil, nil
	}
	resourcesChanged := !changedTypeURLs.Empty()
	if !resourcesChanged {
		updated, err := tx.applyPreparedResourcesLocked(resourceChanges{}, inverseResources{}, typeurl.NewSet(), typeurl.NewSet(), false, mutations, wg, updatedTypeURLs, nil, restoredEntries)
		return updated, nil, err
	}
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	var lifecycle *rollbackLifecycle
	if restoredEntries == nil {
		lifecycle = c.newCallerRollbackLifecycle(tx.ctx, tx.nodeID, tx.generation, inverse)
	}
	watchTypeURLs := changedTypeURLs
	if !stateExists {
		changedTypeURLs = typeurl.Set{}
	}
	updated, err := tx.applyPreparedResourcesLocked(changes, inverse, changedTypeURLs, watchTypeURLs, true, mutations, wg, updatedTypeURLs, lifecycle, restoredEntries)
	if err != nil {
		return false, nil, err
	}
	if inverse.len(typeurl.Listener) > 0 {
		tx.listenerChanges = committedListenerChanges(changes)
	}
	if lifecycle == nil {
		return updated, nil, nil
	}
	return updated, lifecycle, nil
}

// retainUnsentRollbackLocked keeps one coalesced rollback for a resource type
// until go-control-plane produces a response carrying the current version.
// Registering it with the completion callbacks immediately also lets a
// version-only request prove that the version was already accepted after a
// reconnect, without requiring an OnStreamResponse callback in this process.
func (c *cacheImpl) retainUnsentRollbackLocked(nodeID string, typeURL typeurl.Index, generation uint64, rollback rollbackResources) {
	state := c.nodeStates[nodeID]
	if state == nil {
		state = &nodeState{}
		c.nodeStates[nodeID] = state
	}
	if existing, exists := state.unsentRollbacks.Get(typeURL); exists && existing != nil && !existing.completedLocked() {
		if c.completionCbs.CoalesceUnsentTypeGeneration(nodeID, typeURL, existing.generation, generation) {
			*existing.resources = existing.resources.mergeHistory(state, rollback)
			existing.generation = generation
			return
		}
		// A response claimed the existing generation before its callback ran.
		// Leave that lifecycle response-owned and start another unsent chain.
		state.unsentRollbacks.Remove(typeURL)
	}

	// Response rollback must outlive the context of the mutation which created
	// it. A later NACK remains actionable after that caller has timed out.
	lifecycle := c.newRollbackLifecycle(context.Background(), nodeID, typeURL, generation, rollback)
	registered, _ := c.completionCbs.AddTypeGenerationWithRollback(
		generation, "", typeURL, nodeID, true, lifecycle)
	if !registered {
		lifecycle.finalizeLocked()
		return
	}
	state.unsentRollbacks.Set(typeURL, lifecycle)
}

func (c *cacheImpl) claimUnsentRollbackLocked(nodeID string, typeURL typeurl.Index) {
	state := c.nodeStates[nodeID]
	if state == nil || !state.unsentRollbacks.Has(typeURL) {
		return
	}
	state.unsentRollbacks.Remove(typeURL)
}

// newRollbackLifecycle owns one rollback view until it is either finalized or
// reverted. Duplicate resolution calls are programming errors, but are
// deliberately harmless because the lifecycle crosses several asynchronous
// ownership boundaries.
func (c *cacheImpl) newRollbackLifecycle(ctx context.Context, nodeID string, typeURL typeurl.Index, generation uint64, resources rollbackResources) *rollbackLifecycle {
	return &rollbackLifecycle{
		cache:      c,
		ctx:        ctx,
		nodeID:     nodeID,
		typeURL:    typeURL,
		generation: generation,
		resources:  &resources,
	}
}

func (c *cacheImpl) newCallerRollbackLifecycle(ctx context.Context, nodeID string, generation uint64, inverse inverseResources) *rollbackLifecycle {
	return &rollbackLifecycle{
		cache:      c,
		ctx:        ctx,
		nodeID:     nodeID,
		typeURL:    typeurl.Count,
		generation: generation,
		inverse:    inverse,
	}
}

func (lifecycle *rollbackLifecycle) warnDuplicateLocked(action string) {
	lifecycle.cache.logger.Warn("Ignoring duplicate resource update rollback resolution",
		logfields.NodeID, lifecycle.nodeID,
		logfields.XDSGeneration, lifecycle.generation,
		logfields.Operation, action)
}

func (lifecycle *rollbackLifecycle) detachUnsentLocked() {
	if lifecycle.typeURL >= typeurl.Count {
		return
	}
	state := lifecycle.cache.nodeStates[lifecycle.nodeID]
	if state == nil {
		return
	}
	existing, exists := state.unsentRollbacks.Get(lifecycle.typeURL)
	if !exists || existing != lifecycle {
		return
	}
	state.unsentRollbacks.Remove(lifecycle.typeURL)
}

// completedLocked reports whether finalization or reversion has consumed the
// lifecycle's rollback payload. Caller must hold cacheImpl.mutex.
func (lifecycle *rollbackLifecycle) completedLocked() bool {
	return lifecycle.resources == nil && lifecycle.inverse.empty()
}

// takeRollbackLocked atomically resolves the lifecycle and returns its rollback
// payload. Clearing both payload representations marks the lifecycle resolved
// while retaining identifying fields for duplicate warnings.
// Caller must hold cacheImpl.mutex.
func (lifecycle *rollbackLifecycle) takeRollbackLocked(action string) (*rollbackResources, inverseResources, bool) {
	if lifecycle.completedLocked() {
		lifecycle.warnDuplicateLocked(action)
		return nil, inverseResources{}, false
	}
	resources, inverse := lifecycle.resources, lifecycle.inverse
	lifecycle.resources = nil
	lifecycle.inverse = inverseResources{}
	lifecycle.detachUnsentLocked()
	return resources, inverse, true
}

func (lifecycle *rollbackLifecycle) finalizeLocked() {
	resources, inverse, ok := lifecycle.takeRollbackLocked("finalize")
	if !ok {
		return
	}
	if state := lifecycle.cache.nodeStates[lifecycle.nodeID]; state != nil {
		if resources == nil {
			state.releaseInverseRollback(inverse, lifecycle.generation)
		} else {
			state.releaseRollback(*resources)
		}
	}
}

// Finalize releases the caller-owned rollback state after the enclosing
// transaction succeeds.
func (lifecycle *rollbackLifecycle) Finalize() {
	c := lifecycle.cache
	c.mutex.Lock()
	lifecycle.finalizeLocked()
	c.mutex.Unlock()
}

// Revert restores caller-owned state after the enclosing transaction fails.
func (lifecycle *rollbackLifecycle) Revert() error {
	_, _ = lifecycle.RevertGeneration(0)
	return nil
}

// RevertGeneration restores response-owned state while threading the resource
// generation fence through a coalesced NACK chain.
func (lifecycle *rollbackLifecycle) RevertGeneration(expectedGeneration uint64) (uint64, bool) {
	c := lifecycle.cache
	tx := c.beginResourceTransaction(lifecycle.ctx, lifecycle.nodeID)
	resources, inverse, ok := lifecycle.takeRollbackLocked("revert")
	if !ok {
		currentGeneration := tx.currentResourceGeneration()
		tx.complete()
		return currentGeneration, false
	}

	currentGeneration := tx.currentResourceGeneration()
	state := tx.state
	var changes resourceChanges
	var restoredEntries resourceEntrySlots
	if resources == nil {
		changes, restoredEntries = state.resourceRevertInverse(lifecycle.generation, inverse)
	} else {
		changes, restoredEntries = state.resourceRevert(*resources)
	}
	if state != nil {
		if resources == nil {
			state.releaseInverseRollback(inverse, lifecycle.generation)
		} else {
			state.releaseRollback(*resources)
		}
	}
	if changes.empty() {
		tx.complete()
		c.logger.Debug(
			"Skipping revert, affected resources have been superseded",
			logfields.NodeID, lifecycle.nodeID,
			logfields.XDSPushedGeneration, lifecycle.generation,
			logfields.XDSExpectedGeneration, expectedGeneration,
			logfields.XDSCurrentGeneration, currentGeneration,
		)
		return currentGeneration, false
	}

	c.logger.Debug("Reverting snapshot for node", logfields.NodeID, lifecycle.nodeID)
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	changedTypeURLs := changes.typeURLs()
	err := tx.updateResourceChangesLocked(changes, changes.inverse(), snapshotTypesChangedBy(changedTypeURLs), changedTypeURLs,
		c.defaultGenerator, nil, typeURLWaits{}, nil, &restoredEntries)
	tx.listenerChanges = committedListenerChanges(changes)
	currentGeneration = tx.currentResourceGeneration()
	tx.complete()
	if err != nil {
		c.logger.Error("Failed to revert snapshot",
			logfields.NodeID, lifecycle.nodeID,
			logfields.Error, err)
		return currentGeneration, false
	}
	return currentGeneration, true
}

func resourceMutationAccepted[V interface {
	proto.Message
	comparable
}](completionCbs *callbacks.CompletionCallbacks, nodeID string, typeURL typeurl.Index, current map[string]resourceEntry, removed, upserted map[string]V, typeChanged bool) bool {
	if len(removed) == 0 && len(upserted) == 0 {
		return false
	}
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		if !completionCbs.ResourceAccepted(nodeID, typeURL, name, nil, false) {
			return false
		}
	}
	for name, resource := range upserted {
		// prepareResourceMutation has already established semantic equality
		// for unchanged types. Reuse the canonical cache pointer here so an
		// already-ACKed no-op does not pay for the same semantic comparison twice.
		if !typeChanged {
			if cached, exists := currentResource(current, name); exists {
				resource = cached.(V)
			}
		}
		if !completionCbs.ResourceAccepted(nodeID, typeURL, name, resource, true) {
			return false
		}
	}
	return true
}

// resourceMutationGeneration returns the newest generation among the resource
// names supplied for one TypeURL. The boolean distinguishes an absent mutation
// from a mutation of a resource whose generation is legitimately zero.
func resourceMutationGeneration[V comparable](current map[string]resourceEntry, removed, upserted map[string]V) (uint64, bool) {
	var generation uint64
	found := false
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		found = true
		generation = max(generation, current[name].generation)
	}
	for name := range upserted {
		found = true
		generation = max(generation, current[name].generation)
	}
	return generation, found
}

func (state *nodeState) mutationGeneration(typeURL typeurl.Index, mutations ResourceMutations) uint64 {
	var found bool
	var generation uint64
	switch typeURL {
	case typeurl.Listener:
		generation, found = resourceMutationGeneration(state.resourceEntries(typeurl.Listener), mutations.Removed.Listeners, mutations.Upserted.Listeners)
	case typeurl.Route:
		generation, found = resourceMutationGeneration(state.resourceEntries(typeurl.Route), mutations.Removed.Routes, mutations.Upserted.Routes)
	case typeurl.Cluster:
		generation, found = resourceMutationGeneration(state.resourceEntries(typeurl.Cluster), mutations.Removed.Clusters, mutations.Upserted.Clusters)
	case typeurl.Endpoint:
		generation, found = resourceMutationGeneration(state.resourceEntries(typeurl.Endpoint), mutations.Removed.Endpoints, mutations.Upserted.Endpoints)
	case typeurl.Secret:
		generation, found = resourceMutationGeneration(state.resourceEntries(typeurl.Secret), mutations.Removed.Secrets, mutations.Upserted.Secrets)
	}
	if found {
		return generation
	}
	return state.generationForType(typeURL)
}

// generationForType returns the generation of the staged or published
// snapshot which currently represents typeURL.
func (state *nodeState) generationForType(typeURL typeurl.Index) uint64 {
	if state == nil {
		return 0
	}
	if state.staged != nil {
		if state.staged.changedTypeURLs.Has(typeURL) {
			return state.staged.generation
		}
	}
	return state.snapshotGeneration
}

func (tx *resourceTransaction) resourcesAcceptedLocked(typeURL typeurl.Index, mutations ResourceMutations, typeChanged bool) bool {
	c := tx.cache
	state := tx.state
	if state == nil {
		return false
	}
	switch typeURL {
	case typeurl.Listener:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources[typeurl.Listener].entries, mutations.Removed.Listeners, mutations.Upserted.Listeners, typeChanged)
	case typeurl.Route:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources[typeurl.Route].entries, mutations.Removed.Routes, mutations.Upserted.Routes, typeChanged)
	case typeurl.Cluster:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources[typeurl.Cluster].entries, mutations.Removed.Clusters, mutations.Upserted.Clusters, typeChanged)
	case typeurl.Endpoint:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources[typeurl.Endpoint].entries, mutations.Removed.Endpoints, mutations.Upserted.Endpoints, typeChanged)
	case typeurl.Secret:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources[typeurl.Secret].entries, mutations.Removed.Secrets, mutations.Upserted.Secrets, typeChanged)
	default:
		return false
	}
}

// generateSnapshotForUpdate is shared by every production mutation. Tests may
// still supply a custom generator to updateResources when they need to observe
// lazy finalization directly.
func (c *cacheImpl) generateSnapshotForUpdate(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error) {
	snapshot, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	if err != nil {
		return nil, err
	}
	if c.strictAdsMode {
		if err := CheckSnapshotConsistency(snapshot); err != nil {
			return nil, fmt.Errorf("generated ADS snapshot is inconsistent: %w", err)
		}
	}
	return snapshot, nil
}

// applyPreparedResourcesLocked stages resources only when their semantic contents changed.
// Completion-only updates are attached to the current version of that resource
// type. For a mixed update, completions are split between resource types made
// dirty by this generation and types which remain at their current version.
// Caller must hold mutex.
func (tx *resourceTransaction) applyPreparedResourcesLocked(changes resourceChanges, inverse inverseResources, changedTypeURLs, watchTypeURLs typeurl.Set, resourcesChanged bool, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks, lifecycle *rollbackLifecycle, restoredEntries *resourceEntrySlots) (bool, error) {
	var dirtyTypeURLs typeurl.Set
	if resourcesChanged {
		dirtyTypeURLs = snapshotTypesChangedBy(changedTypeURLs)
	}
	var changedWaits, unchangedWaits typeURLWaits
	for typeURL, callback := range updatedTypeURLs.All() {
		typeChanged := changedTypeURLs.Has(typeURL)
		if tx.resourcesAcceptedLocked(typeURL, mutations, typeChanged) {
			tx.addAcceptedCallback(wg, callback)
			continue
		}
		if dirtyTypeURLs.Has(typeURL) {
			changedWaits.Set(typeURL, generationWait{
				callback:   callback,
				generation: tx.generation,
			})
		} else {
			unchangedWaits.Set(typeURL, generationWait{
				callback:   callback,
				generation: tx.state.mutationGeneration(typeURL, mutations),
			})
		}
	}
	if !resourcesChanged {
		err := tx.awaitCurrentVersionLocked(wg, unchangedWaits)
		return false, err
	}
	err := tx.updateResourceChangesLocked(changes, inverse, dirtyTypeURLs, watchTypeURLs, tx.cache.defaultGenerator, wg, changedWaits, lifecycle, restoredEntries)
	if err != nil {
		return false, err
	}
	err = tx.awaitCurrentVersionLocked(wg, unchangedWaits)
	if err != nil {
		return true, err
	}
	return true, nil
}

// updateResourceChangesLocked commits one prepared mutation and optionally
// finalizes it for an open watch. Caller must hold mutex; post-lock work is
// accumulated on tx.
func (tx *resourceTransaction) updateResourceChangesLocked(changes resourceChanges, inverse inverseResources, dirtyTypeURLs, watchTypeURLs typeurl.Set, generator snapshotGenerator, wg *completion.WaitGroup, waits typeURLWaits, lifecycle *rollbackLifecycle, restoredEntries *resourceEntrySlots) error {
	c := tx.cache
	// Snapshot dependencies can make dirtyTypeURLs broader than the mutation.
	// Responses are ACKed or NACKed independently by TypeURL, so retain rollback
	// state only for resource types directly changed by this transaction.
	rollbackTypeURLs := watchTypeURLs

	state := tx.state
	stateExisted := state != nil
	if state == nil {
		state = &nodeState{}
		c.nodeStates[tx.nodeID] = state
		tx.state = state

		// The first desired state must establish a complete baseline for whichever
		// supported resource type Envoy requests first.
		watchTypeURLs = snapshotTypesChangedBy(typeurl.Set{})
	}
	oldResourceGeneration := state.resourceGeneration
	state.commitResourceMutation(changes, tx.generation, restoredEntries)
	if lifecycle != nil {
		state.updateInverseRollbackOwners(lifecycle.inverse, lifecycle.generation, 1)
	}
	networkPolicyStateEmpty := state.networkPoliciesEmpty()
	completions, immediateCompletions := c.registerStagedGenerationCompletions(
		tx.nodeID, networkPolicyStateEmpty, wg, waits, nil)
	oldStaged := state.staged
	var oldStagedValue stagedSnapshot
	mergedTypeURLs := dirtyTypeURLs
	completionTypeURLs := dirtyTypeURLs
	var rollbacks typeurl.Map[rollbackResources]
	if oldStaged != nil {
		oldStagedValue = *oldStaged
		mergedTypeURLs = oldStaged.changedTypeURLs.Union(dirtyTypeURLs)
		watchTypeURLs = oldStaged.watchTypeURLs.Union(watchTypeURLs)
		completionTypeURLs = oldStaged.completionTypeURLs.Union(dirtyTypeURLs)
		rollbacks = oldStaged.rollbacks
	}
	willFinalize := c.hasOpenWatchLocked(tx.nodeID, watchTypeURLs)
	if willFinalize && oldStaged != nil {
		// Only publication can fail after resources have been committed. Keep a
		// defensive copy for that rare path without cloning the growing staged
		// rollback map on every ordinary mutation.
		oldStagedValue.rollbacks = cloneStagedRollbacks(oldStaged.rollbacks)
	}
	completionTypeURLs = mergeTypeURLWaits(completionTypeURLs, waits)
	if lifecycle != nil {
		rollbacks = state.mergeStagedRollbacks(rollbacks, rollbackTypeURLs, lifecycle.inverse, tx.generation, c.strictAdsMode)
	}
	staged := oldStaged
	if staged == nil {
		staged = &stagedSnapshot{}
	}
	*staged = stagedSnapshot{
		generation:         tx.generation,
		changedTypeURLs:    mergedTypeURLs,
		watchTypeURLs:      watchTypeURLs,
		completionTypeURLs: completionTypeURLs,
		rollbacks:          rollbacks,
		generator:          generator,
	}
	state.staged = staged

	var finalized []finalizedCompletion
	var err error
	if willFinalize {
		_, finalized, err = c.finalizeStagedSnapshotLocked(tx.ctx, tx.nodeID)
	}
	deliveries := c.collectResponseDeliveriesLocked()
	if err != nil {
		if lifecycle != nil {
			lifecycle.finalizeLocked()
		}
		if !stateExisted {
			delete(c.nodeStates, tx.nodeID)
			tx.state = nil
		} else {
			inverseEntries := inverse.materialize()
			state.restoreResourceEntries(inverseEntries)
			// Re-establish the old stage ownership before releasing the failed
			// replacement so shared tombstones remain continuously guarded.
			if oldStaged != nil {
				state.acquireRollbackSet(oldStagedValue.rollbacks)
			}
			state.releaseRollbackSet(rollbacks)
			published, _ := c.SnapshotCache.GetSnapshot(tx.nodeID)
			state.reconcileChangedResourceNames(inverseEntries, published)
			state.resourceGeneration = oldResourceGeneration
			if oldStaged == nil {
				state.staged = nil
			} else {
				*oldStaged = oldStagedValue
				state.staged = oldStaged
			}
		}
	} else {
		state.resourceGeneration = tx.generation
	}
	tx.deliveries = deliveries
	tx.finalized = finalized
	tx.registeredCompletions = completions
	tx.immediateCompletions = immediateCompletions
	tx.networkPolicyStateEmpty = networkPolicyStateEmpty
	tx.updateFailed = err != nil
	if err != nil {
		return err
	}
	return nil
}

// awaitCurrentVersionLocked registers waits against staged or published state.
// A wait-specific generation allows an ACK for the matching
// resource contents to resolve a semantic no-op even if another resource type
// advanced the node generation.
// Caller must hold mutex; immediate completions are deferred on tx until after
// unlocking.
func (tx *resourceTransaction) awaitCurrentVersionLocked(wg *completion.WaitGroup, waits typeURLWaits) error {
	if wg == nil || waits.Empty() {
		return nil
	}

	c := tx.cache
	state := tx.state
	var staged *stagedSnapshot
	if state != nil {
		staged = state.staged
	}
	if staged != nil {
		var stagedWaits, publishedWaits typeURLWaits
		for typeURL, wait := range waits.All() {
			if staged.changedTypeURLs.Has(typeURL) {
				stagedWaits.Set(typeURL, wait)
			} else {
				publishedWaits.Set(typeURL, wait)
			}
		}
		_, immediateCompletions := c.registerStagedGenerationCompletions(
			tx.nodeID, state.networkPoliciesEmpty(), wg, stagedWaits, nil)
		tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
		if publishedWaits.Empty() {
			return nil
		}
		currentSnapshot, err := c.SnapshotCache.GetSnapshot(tx.nodeID)
		if err != nil {
			return fmt.Errorf("failed to get current snapshot for node %s: %w", tx.nodeID, err)
		}
		_, publishedImmediate := c.registerGenerationCompletions(
			tx.nodeID, currentSnapshot, currentSnapshot, wg, publishedWaits, nil)
		tx.immediateCompletions = append(tx.immediateCompletions, publishedImmediate...)
		return nil
	}

	currentSnapshot, err := c.SnapshotCache.GetSnapshot(tx.nodeID)
	if err != nil {
		return fmt.Errorf("failed to get current snapshot for node %s: %w", tx.nodeID, err)
	}
	_, immediateCompletions := c.registerGenerationCompletions(tx.nodeID, currentSnapshot, currentSnapshot, wg, waits, nil)
	tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
	return nil
}

func (c *cacheImpl) ClearSnapshot(nodeID string) {
	c.mutex.Lock()
	c.SnapshotCache.ClearSnapshot(nodeID)
	c.completionCbs.SetPublishedSnapshot(nodeID, 0, nil)
	c.nodeStates[nodeID] = &nodeState{}
	var cancels []func()
	if state := c.openWatches[nodeID]; state != nil {
		for _, watches := range state.All() {
			for _, watch := range watches {
				if watch.cancel != nil {
					cancels = append(cancels, watch.cancel)
				}
				c.removeTrackedWatchLocked(watch)
			}
		}
	}
	c.mutex.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func normalizeCustomWildcardRequest(request *cache.Request, sub cache.Subscription) *cache.Request {
	if request == nil || sub == nil || !sub.IsWildcard() || len(request.GetResourceNames()) == 0 {
		return request
	}
	switch request.GetTypeUrl() {
	case NetworkPolicyTypeURL, NetworkPolicyHostsTypeURL:
		normalized := proto.Clone(request).(*cache.Request)
		normalized.ResourceNames = nil
		return normalized
	default:
		return request
	}
}

func streamResetNodeID(streamID int64) string {
	return "cilium-stream-reset/" + strconv.FormatInt(streamID, 10)
}

func streamResetSnapshot(streamID int64) *ciliumSnapshot {
	var groups typeurl.Slots[snapshotResourceGroup]
	groups[typeurl.Listener].resources.Version = "cilium-stream-reset-" + strconv.FormatInt(streamID, 10)
	return newCiliumSnapshot(groups)
}

func streamResetRequest(request *cache.Request, streamID int64) *cache.Request {
	resetRequest := proto.Clone(request).(*cache.Request)
	if resetRequest.Node == nil {
		resetRequest.Node = &envoy_config_core.Node{}
	}
	resetRequest.Node.Id = streamResetNodeID(streamID)
	return resetRequest
}

func (c *cacheImpl) streamClosed(streamID int64) {
	c.mutex.Lock()
	c.SnapshotCache.ClearSnapshot(streamResetNodeID(streamID))
	c.mutex.Unlock()
}

func (c *cacheImpl) hasOpenWatchLocked(nodeID string, typeURLs typeurl.Set) bool {
	state := c.openWatches[nodeID]
	if state == nil {
		return false
	}
	for typeURL := range typeURLs.Members() {
		watches, _ := state.Get(typeURL)
		if len(watches) > 0 {
			return true
		}
	}
	return false
}

func (c *cacheImpl) relayForLocked(responseChannel chan cache.Response) *watchRelay {
	if relay := c.watchRelays[responseChannel]; relay != nil {
		return relay
	}
	capacity := max(cap(responseChannel), int(typeurl.Count)+1)
	relay := &watchRelay{
		inner:   make(chan cache.Response, capacity),
		outer:   responseChannel,
		watches: make(map[uint64]*trackedWatch),
	}
	c.watchRelays[responseChannel] = relay
	return relay
}

func (c *cacheImpl) addTrackedWatchLocked(request *cache.Request, typeURL typeurl.Index, responseChannel chan cache.Response, streamID int64, countsAsOpen bool) *trackedWatch {
	c.nextWatchID++
	relay := c.relayForLocked(responseChannel)
	watch := &trackedWatch{
		id:             c.nextWatchID,
		nodeID:         request.GetNode().GetId(),
		typeURL:        typeURL,
		streamID:       streamID,
		request:        request,
		backendRequest: request,
		relay:          relay,
	}
	if countsAsOpen {
		state := c.openWatches[watch.nodeID]
		if state == nil {
			state = &nodeWatchState{}
			c.openWatches[watch.nodeID] = state
		}
		watches, _ := state.Get(watch.typeURL)
		if watches == nil {
			watches = make(map[uint64]*trackedWatch)
			state.Set(watch.typeURL, watches)
		}
		watches[watch.id] = watch
	}
	relay.watches[watch.id] = watch
	return watch
}

func (c *cacheImpl) removeTrackedWatchLocked(watch *trackedWatch) {
	if watch == nil {
		return
	}
	if state := c.openWatches[watch.nodeID]; state != nil {
		watches, exists := state.Get(watch.typeURL)
		if exists {
			delete(watches, watch.id)
			if len(watches) == 0 {
				state.Remove(watch.typeURL)
			}
		}
		if state.Empty() {
			delete(c.openWatches, watch.nodeID)
		}
	}
	if watch.relay != nil {
		delete(watch.relay.watches, watch.id)
		if len(watch.relay.watches) == 0 && len(watch.relay.inner) == 0 {
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
	c.removeTrackedWatchLocked(watch)
	c.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

// collectResponseDeliveriesLocked drains responses which go-control-plane has
// synchronously produced. Draining retires the corresponding type watch before
// another resource update can mistake it for available Envoy capacity.
func (c *cacheImpl) collectResponseDeliveriesLocked() []responseDelivery {
	var deliveries []responseDelivery
	for _, relay := range c.watchRelays {
		var responses []cache.Response
		for {
			select {
			case response := <-relay.inner:
				var matched *trackedWatch
				for _, watch := range relay.watches {
					if watch.backendRequest == response.GetRequest() {
						matched = watch
						break
					}
				}
				if matched != nil {
					if matched.isReset() {
						ctx := response.GetContext()
						if ctx == nil {
							ctx = context.Background()
						}
						response = &trackedResponse{
							Response: response,
							request:  matched.request,
							ctx:      callbacks.WithStreamReset(ctx, matched.streamID),
						}
					} else {
						c.claimUnsentRollbackLocked(matched.nodeID, matched.typeURL)
					}
					c.removeTrackedWatchLocked(matched)
				}
				responses = append(responses, response)
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

func (c *cacheImpl) deliverResponses(deliveries []responseDelivery) {
	for _, delivery := range deliveries {
		for _, response := range delivery.responses {
			delivery.channel <- response
		}
	}
}

// ensureSnapshotForWatchLocked establishes an authoritative empty snapshot for
// a node which has not produced any desired resources since agent startup. It
// deliberately does not create nodeState: connection lifecycle must not own or
// imply desired resource state. Caller must hold mutex.
func (c *cacheImpl) ensureSnapshotForWatchLocked(nodeID string) error {
	if _, err := c.SnapshotCache.GetSnapshot(nodeID); err == nil {
		return nil
	}

	emptySnapshot, err := c.generateSnapshotForUpdate(&nodeState{}, nil, typeurl.Set{})
	if err != nil {
		return err
	}
	c.completionCbs.SetPublishedSnapshot(nodeID, 0, emptySnapshot)
	err = c.SnapshotCache.SetSnapshot(callbacks.WithSnapshotGeneration(context.Background(), 0), nodeID, emptySnapshot)
	if err == nil {
		return nil
	}

	currentSnapshot, getErr := c.SnapshotCache.GetSnapshot(nodeID)
	if getErr == nil && !c.areDifferentSnapshots(currentSnapshot, emptySnapshot) {
		c.logger.Debug("Initial empty snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
		return nil
	}
	c.completionCbs.SetPublishedSnapshot(nodeID, 0, nil)
	return err
}

func (c *cacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	streamID, resetPhase := c.completionCbs.StreamResetStateForRequest(request)
	if request != nil && request.GetTypeUrl() == envoy_resource.SecretType && len(request.GetResourceNames()) == 0 {
		c.logger.Debug("Ignoring empty ADS SDS watch")
		return func() {}, nil
	}
	request = normalizeCustomWildcardRequest(request, sub)
	if request == nil {
		return c.SnapshotCache.CreateWatch(request, sub, respChan)
	}
	typeURL, supported := typeurl.FromURL(request.GetTypeUrl())
	if !supported {
		// Unknown protocol types are outside Cilium's fixed ADS resource set.
		// Preserve go-control-plane behavior without creating internal tracking
		// state which could never be addressed by an indexed mutation.
		return c.SnapshotCache.CreateWatch(request, sub, respChan)
	}

	nodeID := request.GetNode().GetId()
	c.mutex.Lock()
	var finalized []finalizedCompletion
	var deliveries []responseDelivery
	// Retire responses already produced for this stream before handling a reset
	// transition or deciding whether this watch can consume staged state.
	deliveries = append(deliveries, c.collectResponseDeliveriesLocked()...)

	prepareLiveSnapshot := func() error {
		state := c.nodeStates[nodeID]
		if state == nil {
			return c.ensureSnapshotForWatchLocked(nodeID)
		}
		if state.staged != nil && state.staged.watchTypeURLs.Has(typeURL) {
			var newlyFinalized []finalizedCompletion
			_, newlyFinalized, err := c.finalizeStagedSnapshotLocked(context.Background(), nodeID)
			finalized = append(finalized, newlyFinalized...)
			return err
		}
		return nil
	}

	resetWatch := false
	resetTransition := false
	switch resetPhase {
	case callbacks.StreamResetRequested:
		if c.completionCbs.BeginStreamReset(streamID) {
			resetWatch = true
			resetTransition = true
			resetNodeID := streamResetNodeID(streamID)
			err = c.SnapshotCache.SetSnapshot(
				callbacks.WithStreamReset(context.Background(), streamID),
				resetNodeID,
				streamResetSnapshot(streamID),
			)
		} else {
			err = prepareLiveSnapshot()
		}
	case callbacks.StreamResetting:
		resetWatch = true
	case callbacks.StreamResetComplete:
		resetTransition = true
		err = prepareLiveSnapshot()
		if err == nil {
			c.SnapshotCache.ClearSnapshot(streamResetNodeID(streamID))
			c.completionCbs.FinishStreamReset(streamID)
			deliveries = append(deliveries, c.collectResponseDeliveriesLocked()...)
		}
	case callbacks.StreamResetInactive:
		err = prepareLiveSnapshot()
	}

	if err != nil {
		if resetTransition {
			c.completionCbs.AbortStreamReset(streamID)
			c.SnapshotCache.ClearSnapshot(streamResetNodeID(streamID))
		}
		deliveries = append(deliveries, c.collectResponseDeliveriesLocked()...)
		c.mutex.Unlock()
		c.deliverResponses(deliveries)
		if resetPhase == callbacks.StreamResetComplete {
			c.completeFinalized(nodeID, finalized)
		}
		return nil, err
	}

	watch := c.addTrackedWatchLocked(request, typeURL, respChan, streamID, !resetWatch)
	if resetWatch {
		watch.backendRequest = streamResetRequest(request, streamID)
	}
	watch.cancel, err = c.SnapshotCache.CreateWatch(watch.backendRequest, sub, watch.relay.inner)
	if err != nil {
		c.removeTrackedWatchLocked(watch)
	}
	deliveries = append(deliveries, c.collectResponseDeliveriesLocked()...)
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	c.completeFinalized(nodeID, finalized)
	if err != nil {
		return nil, err
	}
	return func() { c.cancelTrackedWatch(watch) }, nil
}

func (state *nodeState) getResource(typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool) {
	if state == nil || typeURL >= typeurl.Count {
		return nil, false
	}
	return currentResource(state.resources[typeURL].entries, resourceName)
}

func (c *cacheImpl) GetResource(nodeID string, typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.nodeStates[nodeID].getResource(typeURL, resourceName)
}

func (c *cacheImpl) Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener] {
	return func(yield func(string, *envoy_config_listener.Listener) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		state := c.nodeStates[nodeID]
		if state == nil {
			return
		}
		for name, entry := range state.resources[typeurl.Listener].entries {
			if entry.resource != nil && !yield(name, typedResource[*envoy_config_listener.Listener](entry.resource)) {
				return
			}
		}
	}
}

func (c *cacheImpl) Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration] {
	return func(yield func(string, *envoy_config_route.RouteConfiguration) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		state := c.nodeStates[nodeID]
		if state == nil {
			return
		}
		for name, entry := range state.resources[typeurl.Route].entries {
			if entry.resource != nil && !yield(name, typedResource[*envoy_config_route.RouteConfiguration](entry.resource)) {
				return
			}
		}
	}
}

func (c *cacheImpl) NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy] {
	return func(yield func(string, *cilium.NetworkPolicy) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		state := c.nodeStates[nodeID]
		if state == nil {
			return
		}
		for name, entry := range state.resources[typeurl.NetworkPolicy].entries {
			if entry.resource != nil && !yield(name, typedResource[*cilium.NetworkPolicy](entry.resource)) {
				return
			}
		}
	}
}

func (c *cacheImpl) areDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for resourceType := range typeurl.Indices() {
		if left.GetVersion(resourceType.URL()) != right.GetVersion(resourceType.URL()) {
			return true
		}
	}
	return false
}
