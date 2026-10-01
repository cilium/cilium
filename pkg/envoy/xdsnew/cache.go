// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"iter"
	"log/slog"
	"slices"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
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

type Cache interface {
	cache.SnapshotCache

	// ApplyResources stages semantic changes and retains cache-owned NACK
	// rollback. Completions for unchanged resource types attach to their current
	// version instead of creating a completion-only generation.
	ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) error
	// ApplyResourcesWithRollback also returns a caller-owned rollback lifecycle
	// for a changed update. The caller must eventually Finalize or Revert it.
	ApplyResourcesWithRollback(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (Rollback, error)
	// ApplyResource compares only the named resource and builds a sparse mutation
	// only after detecting an actual semantic change. It accepts every supported
	// typeURL. A nil resource removes the named resource; typeURL identifies its
	// type even for removals.
	ApplyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error)) error
	// ApplyResourceWithRollback also returns a caller-owned rollback lifecycle
	// for a changed update. The caller must eventually Finalize or Revert it.
	ApplyResourceWithRollback(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error)) (Rollback, error)
	// GetResource returns one cache-owned immutable resource without
	// materializing the complete desired resource maps.
	GetResource(nodeID string, typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool)
	// Resource iterators expose cache-owned immutable resources without
	// leaking the mutable internal maps. Iteration holds the cache read lock,
	// so loop bodies must not call back into the cache.
	Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener]
	Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration]
	NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy]
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
}

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
// the single-resource API, so they cannot share a transaction with a Listener.
// Unchanged resource maps remain nil. Keeping the Resources values inline lets
// callers keep the sparse headers on their stack; only referenced maps escape.
type ResourceMutations struct {
	Removed  xds.Resources
	Upserted xds.Resources
}

// resourceChange is one semantic change to the cache-private desired state.
// The protobufs are immutable; a nil next.resource removes the named resource.
// Both entries retain their generations: normal updates assign a new generation,
// while rollback restores the original entry, including zero for prior absence.
// previous also permits recovery if snapshot publication fails.
type resourceChange struct {
	typeURL  typeurl.Index
	name     string
	previous resourceEntry
	next     resourceEntry
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

// strictReferenceCounts indexes the children referenced by the desired LDS and
// CDS resources. Strict ADS checks only names touched by a transaction; the
// index is built once per node and then updated alongside committed resources.
type strictReferenceCounts struct {
	routes    map[string]int
	endpoints map[string]int
}

type strictConsistencyCandidate struct {
	referenceDelta int
	resource       cache_types.Resource
	// A nil resource denotes removal, so it cannot also indicate that the
	// transaction left this child untouched.
	changed bool
}

type strictConsistencyChanges struct {
	routes    map[string]strictConsistencyCandidate
	endpoints map[string]strictConsistencyCandidate
}

func (changes *resourceChanges) add(typeURL typeurl.Index, name string, previous, next resourceEntry) {
	change := resourceChange{typeURL: typeURL, name: name, previous: previous, next: next}
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

func (changes resourceChanges) hasRemovals() bool {
	if !changes.empty() && changes.first.next.resource == nil {
		return true
	}
	for _, change := range changes.more {
		if change.next.resource == nil {
			return true
		}
	}
	return false
}

func (changes resourceChanges) typeURLs() typeurl.Set {
	if !changes.types.Known() {
		return typeurl.NewSet()
	}
	return changes.types
}

func (changes resourceChanges) affectsStrictConsistency() bool {
	return changes.types.Has(typeurl.Listener) || changes.types.Has(typeurl.Route) ||
		changes.types.Has(typeurl.Cluster) || changes.types.Has(typeurl.Endpoint)
}

func (changes resourceChanges) resourceAfter(typeURL typeurl.Index, name string, current cache_types.Resource) cache_types.Resource {
	if !changes.empty() && changes.first.typeURL == typeURL && changes.first.name == name {
		return changes.first.next.resource
	}
	for _, change := range changes.more {
		if change.typeURL == typeURL && change.name == name {
			return change.next.resource
		}
	}
	return current
}

// strictParentReferences uses the same extractor as the final snapshot check,
// including RDS references in default filter chains and scoped routes.
func strictParentReferences(parent cache_types.Resource, childTypeURL typeurl.Index) map[string]bool {
	if parent == nil {
		return nil
	}
	return cache.GetResourceReferences(map[string]cache_types.ResourceWithTTL{
		"": {Resource: parent},
	})[envoy_resource.Type(childTypeURL.URL())]
}

func (state *nodeState) ensureStrictReferences() *strictReferenceCounts {
	if state.strictRefs != nil {
		return state.strictRefs
	}
	refs := &strictReferenceCounts{}
	for _, entry := range state.resources[typeurl.Listener].entries {
		for name := range strictParentReferences(entry.resource, typeurl.Route) {
			if refs.routes == nil {
				refs.routes = make(map[string]int)
			}
			refs.routes[name]++
		}
	}
	for _, entry := range state.resources[typeurl.Cluster].entries {
		for name := range strictParentReferences(entry.resource, typeurl.Endpoint) {
			if refs.endpoints == nil {
				refs.endpoints = make(map[string]int)
			}
			refs.endpoints[name]++
		}
	}
	state.strictRefs = refs
	return refs
}

func (changes *strictConsistencyChanges) addRouteReference(name string, delta int) {
	if changes.routes == nil {
		changes.routes = make(map[string]strictConsistencyCandidate)
	}
	candidate := changes.routes[name]
	candidate.referenceDelta += delta
	changes.routes[name] = candidate
}

func (changes *strictConsistencyChanges) addEndpointReference(name string, delta int) {
	if changes.endpoints == nil {
		changes.endpoints = make(map[string]strictConsistencyCandidate)
	}
	candidate := changes.endpoints[name]
	candidate.referenceDelta += delta
	changes.endpoints[name] = candidate
}

func (changes *strictConsistencyChanges) add(change resourceChange) {
	switch change.typeURL {
	case typeurl.Listener:
		for name := range strictParentReferences(change.previous.resource, typeurl.Route) {
			changes.addRouteReference(name, -1)
		}
		for name := range strictParentReferences(change.next.resource, typeurl.Route) {
			changes.addRouteReference(name, 1)
		}
	case typeurl.Route:
		changes.addRouteReference(change.name, 0)
		candidate := changes.routes[change.name]
		candidate.resource, candidate.changed = change.next.resource, true
		changes.routes[change.name] = candidate
	case typeurl.Cluster:
		for name := range strictParentReferences(change.previous.resource, typeurl.Endpoint) {
			changes.addEndpointReference(name, -1)
		}
		for name := range strictParentReferences(change.next.resource, typeurl.Endpoint) {
			changes.addEndpointReference(name, 1)
		}
		// The presence of a Cluster with this exact map key determines whether
		// a legacy :* CLA is included or filtered from the snapshot.
		if strings.HasSuffix(change.name, ":*") {
			changes.addEndpointReference(change.name, 0)
		}
	case typeurl.Endpoint:
		changes.addEndpointReference(change.name, 0)
		candidate := changes.endpoints[change.name]
		candidate.resource, candidate.changed = change.next.resource, true
		changes.endpoints[change.name] = candidate
	}
}

func (state *nodeState) validateStrictConsistency(changes resourceChanges) (strictConsistencyChanges, error) {
	refs := state.ensureStrictReferences()
	var proposed strictConsistencyChanges
	proposed.add(changes.first)
	for _, change := range changes.more {
		proposed.add(change)
	}

	for name, candidate := range proposed.routes {
		count := refs.routes[name] + candidate.referenceDelta
		if count < 0 {
			return strictConsistencyChanges{}, fmt.Errorf("negative RDS reference count for %q", name)
		}
		resource := state.resources[typeurl.Route].entries[name].resource
		if candidate.changed {
			resource = candidate.resource
		}
		if count == 0 && resource != nil {
			return strictConsistencyChanges{}, fmt.Errorf("orphan RDS resource %q", name)
		}
		if count > 0 && (name == "" || resource == nil) {
			return strictConsistencyChanges{}, fmt.Errorf("missing RDS resource %q", name)
		}
	}

	for name, candidate := range proposed.endpoints {
		count := refs.endpoints[name] + candidate.referenceDelta
		if count < 0 {
			return strictConsistencyChanges{}, fmt.Errorf("negative EDS reference count for %q", name)
		}
		if count > 0 && name == "" {
			return strictConsistencyChanges{}, fmt.Errorf("missing EDS resource %q", name)
		}
		resource := state.resources[typeurl.Endpoint].entries[name].resource
		if candidate.changed {
			resource = candidate.resource
		}
		// An absent CLA is synthesized for its EDS Cluster. An explicit :*
		// CLA, however, is filtered unless a Cluster has the same map key.
		projected := count > 0 && resource == nil
		if resource != nil {
			projected = true
			if strings.HasSuffix(name, ":*") {
				cluster := changes.resourceAfter(typeurl.Cluster, name, state.resources[typeurl.Cluster].entries[name].resource)
				projected = cluster != nil
			}
		}
		if count == 0 && projected {
			return strictConsistencyChanges{}, fmt.Errorf("orphan EDS resource %q", name)
		}
		if count > 0 && !projected {
			return strictConsistencyChanges{}, fmt.Errorf("missing EDS resource %q", name)
		}
	}
	return proposed, nil
}

func (refs *strictReferenceCounts) apply(changes strictConsistencyChanges, factor int) {
	for name, candidate := range changes.routes {
		if candidate.referenceDelta == 0 {
			continue
		}
		count := refs.routes[name] + factor*candidate.referenceDelta
		if count == 0 {
			delete(refs.routes, name)
		} else {
			if refs.routes == nil {
				refs.routes = make(map[string]int)
			}
			refs.routes[name] = count
		}
	}
	for name, candidate := range changes.endpoints {
		if candidate.referenceDelta == 0 {
			continue
		}
		count := refs.endpoints[name] + factor*candidate.referenceDelta
		if count == 0 {
			delete(refs.endpoints, name)
		} else {
			if refs.endpoints == nil {
				refs.endpoints = make(map[string]int)
			}
			refs.endpoints[name] = count
		}
	}
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
	// When both are needed, this lock precedes go-control-plane's internal
	// locks. Tracked response sends must not wait for a stream consumer while
	// either lock is held.
	mutex *lock.RWMutex
	// nodeStates hold the private desired resources for each node.
	nodeStates map[string]*nodeState
	// Responses are relayed through cache-owned channels so response-owned
	// rollback state is claimed before it can be coalesced with a later update.
	openWatches   map[string]*nodeWatchState
	watchRelays   map[chan cache.Response]*watchRelay
	logger        *slog.Logger
	strictAdsMode bool
	completionCbs *callbacks.CompletionCallbacks
	// resourceGeneration is the global resource-state sequence protected by
	// mutex.
	resourceGeneration uint64
	// listenerObserver is supplied by the ADS server. A nil observer leaves
	// standalone cache users' explicit ACK waits unchanged.
	listenerObserver ListenerObserver
}

type snapshotPublication struct {
	generation         uint64
	completionTypeURLs typeurl.Set
	rollbacks          typeurl.Map[rollbackResources]
}

type rollbackTracking uint8

const (
	noRollbackTracking                rollbackTracking = iota // response-driven reverts and test-only snapshot updates
	responseRollbackTracking                                  // cache-owned NACK rollback only
	callerAndResponseRollbackTracking                         // cache-owned NACK and caller-owned rollback
)

// nodeState separates cache-private desired state from the immutable snapshot
// published to Envoy.
type nodeState struct {
	// Every successful mutation publishes eagerly, so these generations advance
	// together. Both are retained for completion and rollback bookkeeping.
	resourceGeneration uint64
	snapshotGeneration uint64
	// resources owns the current desired state, including generation-tagged
	// removal tombstones.
	resources cacheResources
	// strictRefs is allocated only for strict ADS nodes when a mutation first
	// touches LDS/RDS or CDS/EDS consistency. Nil means not yet indexed.
	strictRefs *strictReferenceCounts
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

// resourceTypeState groups the desired resource entries for one TypeURL.
type resourceTypeState struct {
	entries map[string]resourceEntry
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
}

// cacheResources is the cache-private, generation-aware counterpart of
// xds.Resources. It deliberately excludes PortAllocationCallbacks, which are
// server-side listener bookkeeping rather than xDS resources. The TypeURL slot
// determines the concrete generated protobuf type stored in each map.
type cacheResources typeurl.Slots[resourceTypeState]

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

func (entry rollbackEntry) previousEquals(resource cache_types.Resource) bool {
	previous := entry.previous.resource
	return previous == resource ||
		(previous != nil && resource != nil && xds.ResourceEqual(previous, resource))
}

type rollbackResources typeurl.Slots[map[string]rollbackEntry]

func (rollback rollbackResources) empty() bool {
	for typeURL := range typeurl.Indices() {
		if len(rollback[typeURL]) != 0 {
			return false
		}
	}
	return true
}

type rollbackLifecycle struct {
	cache      *cacheImpl
	ctx        context.Context
	nodeID     string
	typeURL    typeurl.Index
	generation uint64
	resources  *rollbackResources
	inverse    inverseResources
}

// nodeWatchState indexes open watches by resource type. Each type can have
// multiple watches because several streams can subscribe for the same node.
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
	nodeID  string
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

// snapshotResourceGroup keeps the published resources and their per-resource
// versions together. Every resource in resources.Items has a corresponding
// entry in versions.
type snapshotResourceGroup struct {
	resources cache.Resources
	versions  map[string]string
}

// ciliumSnapshot implements go-control-plane's ResourceSnapshot interface for
// both Envoy core resources and Cilium-specific xDS resources. Its version maps
// are constructed with the resource groups, so creating a watch does not need
// to marshal and hash the resources again or mutate the published snapshot.
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

func (c *cacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return c.completionCbs
}

type immediateCompletion struct {
	comp       *completion.Completion
	typeURL    typeurl.Index
	generation uint64
	err        error
}

// generationWait describes one ACK/NACK wait. generation identifies either the
// last mutation of the matching resource or the published snapshot which
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

	generation            uint64
	deliveries            []responseDelivery
	finalized             []finalizedCompletion
	registeredCompletions set.Set[*completion.Completion]
	immediateCompletions  []immediateCompletion
	listenerChanges       []ListenerChange
	updateErr             error
	acceptedCallback      func(error)   // single callback common case
	acceptedCallbacks     []func(error) // additional callbacks
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
	if tx.updateErr == nil && tx.state != nil && len(tx.listenerChanges) > 0 &&
		c.listenerObserver != nil && c.listenerObserver.ApplyCommittedChanges(tx.nodeID, tx.listenerChanges) {
		// Detach while holding the cache lock. A new policy update can
		// register a wait after a listener is re-added, even if its
		// resource generation predates this removal.
		noListenerWaiters = c.completionCbs.TakePendingWaiters(tx.nodeID, typeurl.NetworkPolicy)
	}
	c.mutex.Unlock()
	c.deliverResponses(tx.deliveries)
	if tx.updateErr != nil {
		// Unchanged-resource waits may have been registered before publication.
		// Detach every transaction-owned wait before invoking its callback.
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
	c.completeFinalized(tx.nodeID, tx.finalized)
	c.completeImmediateCompletions(tx.nodeID, tx.immediateCompletions)
	noListenerWaiters.Complete(nil)
	if tx.acceptedCallback != nil {
		tx.acceptedCallback(nil)
		for _, callback := range tx.acceptedCallbacks {
			callback(nil)
		}
	}
}

func (c *cacheImpl) registerGenerationCompletions(nodeID string, snapshot cache.ResourceSnapshot, wg *completion.WaitGroup, waits typeURLWaits) (set.Set[*completion.Completion], []immediateCompletion) {
	var completions set.Set[*completion.Completion]
	// Do not preallocate: immediate completions are uncommon, and reserving
	// capacity here adds an allocation to every resource update.
	var immediateCompletions []immediateCompletion
	if wg != nil && !waits.Empty() {
		for typeURL, wait := range waits.All() {
			owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, wait.generation)
			comp := wg.AddCompletionWithCallback(owner, wait.callback)
			version := snapshot.GetVersion(typeURL.URL())
			registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, version, false)
			if !registered {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:       comp,
					typeURL:    typeURL,
					generation: wait.generation,
					err:        err,
				})
				continue
			}
			completions.Insert(comp)
		}
	}
	return completions, immediateCompletions
}

func (c *cacheImpl) registerPrepublicationCompletions(nodeID string, wg *completion.WaitGroup, waits typeURLWaits) (set.Set[*completion.Completion], []immediateCompletion) {
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
		registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, "", true)
		if !registered {
			immediateCompletions = append(immediateCompletions, immediateCompletion{
				comp:       comp,
				typeURL:    typeURL,
				generation: wait.generation,
				err:        err,
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
		if immediate.err == nil {
			c.completionCbs.CompleteCompletionsThroughGeneration(nodeID, immediate.typeURL, immediate.generation, nil)
		}
		immediate.comp.Complete(immediate.err)
	}
}

func snapshotTypesChangedBy(changedTypeURLs typeurl.Set) typeurl.Set {
	if !changedTypeURLs.Known() {
		return typeurl.All()
	}
	result := changedTypeURLs
	if changedTypeURLs.Has(typeurl.Listener) {
		result = result.Union(listenerDependentTypeURLs)
	}
	if changedTypeURLs.Has(typeurl.Cluster) {
		result = result.Union(clusterDependentTypeURLs)
	}
	return result
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
	default:
		return typeurl.Count, false
	}
}

func (state *nodeState) mergePublicationRollbacks(base typeurl.Map[rollbackResources], typeURLs typeurl.Set, inverse inverseResources, generation uint64, strictADS bool) typeurl.Map[rollbackResources] {
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
		if rollback.empty() {
			base.Remove(typeURL)
		} else {
			base.Set(typeURL, rollback)
		}
	}
	return base
}

func (state *nodeState) releaseRollbackSet(rollbacks typeurl.Map[rollbackResources]) {
	for _, rollback := range rollbacks.All() {
		state.releaseRollback(rollback)
	}
}

// publishSnapshotLocked constructs and installs a snapshot for an accepted
// mutation. The caller holds c.mutex; callbacks are completed after unlocking.
func (c *cacheImpl) publishSnapshotLocked(ctx context.Context, nodeID string, publication snapshotPublication) ([]finalizedCompletion, error) {
	state := c.nodeStates[nodeID]
	oldSnapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	newSnapshot, err := c.generateSnapshotForUpdate(state)
	if err != nil {
		return nil, err
	}

	oldGeneration := state.snapshotGeneration
	// SetSnapshot may synchronously produce a response. Make the generation
	// visible to completion callbacks before handing the snapshot to it.
	c.completionCbs.SetPublishedSnapshot(nodeID, publication.generation, newSnapshot)
	err = c.SnapshotCache.SetSnapshot(callbacks.WithSnapshotGeneration(ctx, publication.generation), nodeID, newSnapshot)
	if err != nil {
		currentSnapshot, getErr := c.SnapshotCache.GetSnapshot(nodeID)
		committed := getErr == nil && !c.areDifferentSnapshots(currentSnapshot, newSnapshot)
		if !committed {
			c.completionCbs.SetPublishedSnapshot(nodeID, oldGeneration, oldSnapshot)
			return nil, err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}

	state.snapshotGeneration = publication.generation
	for typeURL, rollback := range publication.rollbacks.All() {
		if rollback.empty() {
			continue
		}
		versionChanged := oldSnapshot == nil ||
			oldSnapshot.GetVersion(typeURL.URL()) != newSnapshot.GetVersion(typeURL.URL())
		if !versionChanged {
			state.releaseRollback(rollback)
			continue
		}
		c.retainUnsentRollbackLocked(nodeID, typeURL, publication.generation, rollback)
	}
	finalized := make([]finalizedCompletion, 0, publication.completionTypeURLs.Len())
	for typeURL := range publication.completionTypeURLs.Members() {
		version := newSnapshot.GetVersion(typeURL.URL())
		versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL.URL()) != version
		complete, completeErr := c.completionCbs.FinalizeTypeGeneration(
			nodeID, typeURL, publication.generation, version, versionChanged)
		if complete {
			finalized = append(finalized, finalizedCompletion{
				typeURL: typeURL, generation: publication.generation, err: completeErr,
			})
		}
	}
	return finalized, nil
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
}](changes *resourceChanges, typeURL typeurl.Index, generation uint64, current map[string]resourceEntry, removed, upserted map[string]V) {
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		old := current[name]
		if old.resource != nil {
			changes.add(typeURL, name, old, resourceEntry{generation: generation})
		}
	}
	for name, resource := range upserted {
		old := current[name]
		desired := resourceValue(resource)
		if old.resource == desired ||
			(old.resource != nil && desired != nil && xds.ResourceEqual(old.resource, desired)) {
			continue
		}
		changes.add(typeURL, name, old, resourceEntry{resource: desired, generation: generation})
	}
}

// prepareResourceMutation records the proposed next generation without changing
// the cache. The caller reserves it under the cache lock only if changes exist.
func (state *nodeState) prepareResourceMutation(mutations ResourceMutations, generation uint64) (resourceChanges, typeurl.Set, inverseResources) {
	removeSet := mutations.Removed
	upsertSet := mutations.Upserted
	var changes resourceChanges
	prepareResourceMap(&changes, typeurl.Listener, generation, state.resourceEntries(typeurl.Listener), removeSet.Listeners, upsertSet.Listeners)
	prepareResourceMap(&changes, typeurl.Route, generation, state.resourceEntries(typeurl.Route), removeSet.Routes, upsertSet.Routes)
	prepareResourceMap(&changes, typeurl.Cluster, generation, state.resourceEntries(typeurl.Cluster), removeSet.Clusters, upsertSet.Clusters)
	prepareResourceMap(&changes, typeurl.Endpoint, generation, state.resourceEntries(typeurl.Endpoint), removeSet.Endpoints, upsertSet.Endpoints)
	prepareResourceMap(&changes, typeurl.Secret, generation, state.resourceEntries(typeurl.Secret), removeSet.Secrets, upsertSet.Secrets)
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
		// Only an unsent rollback can be coalesced away. No response has
		// exposed any intermediate value, so returning to the original value
		// leaves nothing for a later NACK to restore.
		if exists && entry.previousEquals(desired[name].resource) {
			state.removeRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: entry.expectedGeneration})
			delete(current, name)
			return
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
	if len(current) == 0 {
		return nil
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
			newerEntry.previous = olderEntry.previous
			state.removeRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: olderEntry.expectedGeneration})
			if newerEntry.previousEquals(state.resources[typeURL].entries[name].resource) {
				// The new mutation returned this name to the value preceding the
				// unsent chain. Release the newer removal tombstone as well.
				state.removeRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: newerEntry.expectedGeneration})
				delete(older, name)
				continue
			}
		}
		older[name] = newerEntry
	}
	if len(older) == 0 {
		return nil
	}
	return older
}

func (rollback rollbackResources) mergeHistory(state *nodeState, newer rollbackResources) rollbackResources {
	for typeURL := range typeurl.Indices() {
		rollback[typeURL] = mergeRollbackHistoryMap(state, typeURL, rollback[typeURL], newer[typeURL])
	}
	return rollback
}

func (state *nodeState) resourceRevert(rollback rollbackResources) resourceChanges {
	if state == nil {
		return resourceChanges{}
	}
	var changes resourceChanges
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		for name, entry := range rollback[typeURL] {
			previous := current[name]
			if previous.generation != entry.expectedGeneration ||
				entry.previousEquals(previous.resource) {
				continue
			}
			changes.add(typeURL, name, previous, entry.previous)
		}
	}
	return changes
}

func (state *nodeState) resourceRevertInverse(generation uint64, inverse inverseResources) resourceChanges {
	if state == nil {
		return resourceChanges{}
	}
	var changes resourceChanges
	for typeURL := range typeurl.Indices() {
		current := state.resourceEntries(typeURL)
		for name, previous := range inverse.resources(typeURL) {
			entry := current[name]
			// The inverse only contains semantic changes made by generation.
			// A matching generation therefore cannot already contain previous.
			if entry.generation != generation {
				continue
			}
			changes.add(typeURL, name, entry, previous)
		}
	}
	return changes
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

func (state *nodeState) commitResourceMutation(changes resourceChanges) {
	commit := func(change resourceChange) {
		state.resources[change.typeURL].commitEntry(change.name, change.next)
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

var errEmptyName = errors.New("resource name must not be empty")

func validateResourceMapNames[V any](removed, upserted map[string]V) error {
	if _, exists := removed[""]; exists {
		return errEmptyName
	}
	if _, exists := upserted[""]; exists {
		return errEmptyName
	}
	return nil
}

func validateResourceMutations(mutations ResourceMutations) error {
	removed, upserted := mutations.Removed, mutations.Upserted
	if err := validateResourceMapNames(removed.Listeners, upserted.Listeners); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Routes, upserted.Routes); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Clusters, upserted.Clusters); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Endpoints, upserted.Endpoints); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Secrets, upserted.Secrets); err != nil {
		return err
	}
	return nil
}

// ApplyResources applies sparse removals and upserts to the cache-private
// desired state. It is the authority for semantic no-op detection, changed
// resource names and generation-fenced reverts. Published maps remain immutable;
// a new snapshot is finalized when a watch can consume it.
func (c *cacheImpl) ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) error {
	_, err := c.applyResources(ctx, nodeID, mutations, wg, updatedTypeURLs, responseRollbackTracking)
	return err
}

func (c *cacheImpl) ApplyResourcesWithRollback(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (Rollback, error) {
	return c.applyResources(ctx, nodeID, mutations, wg, updatedTypeURLs, callerAndResponseRollbackTracking)
}

func (c *cacheImpl) applyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks, tracking rollbackTracking) (Rollback, error) {
	if err := validateResourceMutations(mutations); err != nil {
		return nil, err
	}
	tx := c.beginResourceTransaction(ctx, nodeID)
	rollback, err := tx.applyResourcesLocked(mutations, wg, updatedTypeURLs, tracking)
	if err != nil {
		tx.updateErr = err
	}
	tx.complete()
	return rollback, err
}

// finishUnchangedSingleResourceLocked attaches a no-op update directly to the
// resource's current ACK state without constructing a broad ResourceMutations
// value or inspecting unrelated resource types. Caller must hold mutex.
func (tx *resourceTransaction) finishUnchangedSingleResourceLocked(typeURL typeurl.Index, name string, generation uint64, desired proto.Message, desiredExists bool, wg *completion.WaitGroup, callback func(error)) error {
	if wg == nil {
		return nil
	}
	if tx.cache.completionCbs.ResourceAccepted(tx.nodeID, typeURL, name, desired, desiredExists) {
		tx.addAcceptedCallback(wg, callback)
		return nil
	}
	var waits typeURLWaits
	waits.Set(typeURL, generationWait{callback: callback, generation: generation})
	return tx.awaitCurrentVersionLocked(wg, waits)
}

// applyChangedSingleResourceLocked sends an already-prepared typed mutation
// through the shared generation, revert, and lazy-publication machinery. It
// handles completion state directly because the affected resource and TypeURL
// are already known. Caller must hold mutex.
func (tx *resourceTransaction) applyChangedSingleResourceLocked(typeURL typeurl.Index, name string, desired proto.Message, desiredExists bool, inverse inverseResources, wg *completion.WaitGroup, callback func(error), tracking rollbackTracking) (Rollback, error) {
	c := tx.cache
	previous, _ := inverse.get(typeURL, name)
	var changes resourceChanges
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	next := resourceEntry{generation: tx.generation}
	if desiredExists {
		next.resource = desired
	}
	changes.add(typeURL, name, previous, next)
	changedTypeURLs := typeurl.NewSet(typeURL)
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
	err := tx.updateResourceChangesLocked(changes, inverse, dirtyTypeURLs, changedTypeURLs, wg, changedWaits, tracking)
	if err != nil {
		return nil, err
	}
	if accepted {
		tx.addAcceptedCallback(wg, callback)
	}
	if tracking == callerAndResponseRollbackTracking {
		return c.newCallerRollbackLifecycle(tx.ctx, tx.nodeID, tx.generation, inverse), nil
	}
	return nil, nil
}

func (c *cacheImpl) ApplyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error)) error {
	_, err := c.applyResource(ctx, nodeID, typeURL, name, resource, wg, callback, responseRollbackTracking)
	return err
}

func (c *cacheImpl) ApplyResourceWithRollback(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error)) (Rollback, error) {
	return c.applyResource(ctx, nodeID, typeURL, name, resource, wg, callback, callerAndResponseRollbackTracking)
}

func (c *cacheImpl) applyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error), tracking rollbackTracking) (Rollback, error) {
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

	tx := c.beginResourceTransaction(ctx, nodeID)
	defer tx.complete()

	// Do not wait for network policy ACK if there are no NPDS listeners.
	if typeURL == typeurl.NetworkPolicy && wg != nil && c.listenerObserver != nil && !c.listenerObserver.HasNPDSListeners(nodeID) {
		tx.addAcceptedCallback(wg, callback)
		wg = nil
	}

	state := tx.state
	var current map[string]resourceEntry
	if state != nil {
		current = state.resources[typeURL].entries
	}
	previous := current[name]
	desired := resource
	desiredExists := resource != nil
	changed := desiredExists != (previous.resource != nil)
	if desiredExists && previous.resource != nil {
		if previous.resource == resource || xds.ResourceEqual(previous.resource, resource) {
			desired = previous.resource
			changed = false
		} else {
			changed = true
		}
	}
	if !changed {
		if state == nil {
			// Removing a nonexistent resource needs no watch or node state.
			tx.addAcceptedCallback(wg, callback)
			return nil, nil
		}
		return nil, tx.finishUnchangedSingleResourceLocked(typeURL, name, previous.generation, desired, desiredExists, wg, callback)
	}

	// Record listener changes for the observer when the transaction completes.
	if typeURL == typeurl.Listener {
		tx.listenerChanges = []ListenerChange{{
			Previous: typedResource[*envoy_config_listener.Listener](previous.resource),
			Current:  typedResource[*envoy_config_listener.Listener](resource),
		}}
	}
	inverse := singleInverseEntry(typeURL, name, previous)
	return tx.applyChangedSingleResourceLocked(typeURL, name, desired, desiredExists, inverse, wg, callback, tracking)
}

// applyResourcesLocked allocates generations and constructs generation-fenced
// reverts inside the cache. Caller must hold mutex.
func (tx *resourceTransaction) applyResourcesLocked(mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks, tracking rollbackTracking) (Rollback, error) {
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
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(mutations, c.resourceGeneration+1)
	if !stateExists && changedTypeURLs.Empty() {
		for _, callback := range updatedTypeURLs.All() {
			tx.addAcceptedCallback(wg, callback)
		}
		return nil, nil
	}
	var unchangedWaits typeURLWaits
	if changedTypeURLs.Empty() {
		if updatedTypeURLs.Empty() {
			return nil, nil
		}
		for typeURL, callback := range updatedTypeURLs.All() {
			if tx.resourcesAcceptedLocked(typeURL, mutations, false) {
				tx.addAcceptedCallback(wg, callback)
				continue
			}
			unchangedWaits.Set(typeURL, generationWait{
				callback:   callback,
				generation: tx.state.mutationGeneration(typeURL, mutations),
			})
		}
		var err error
		if wg != nil && !unchangedWaits.Empty() {
			err = tx.awaitCurrentVersionLocked(wg, unchangedWaits)
		}
		return nil, err
	}

	// changed, bump to the next generation
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	watchTypeURLs := changedTypeURLs
	if !stateExists {
		changedTypeURLs = typeurl.Set{}
	}

	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
	var changedWaits typeURLWaits
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

	if wg != nil && !unchangedWaits.Empty() {
		err := tx.awaitCurrentVersionLocked(wg, unchangedWaits)
		if err != nil {
			return nil, err
		}
	}

	err := tx.updateResourceChangesLocked(changes, inverse, dirtyTypeURLs, watchTypeURLs, wg, changedWaits, tracking)
	if err != nil {
		return nil, err
	}

	if inverse.len(typeurl.Listener) > 0 {
		tx.listenerChanges = committedListenerChanges(changes)
	}

	if tracking == callerAndResponseRollbackTracking {
		return c.newCallerRollbackLifecycle(tx.ctx, tx.nodeID, tx.generation, inverse), nil
	}
	return nil, nil
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
			if existing.resources.empty() && c.completionCbs.DiscardUnsentTypeGeneration(nodeID, typeURL, generation) {
				// The cache lock prevents a response from claiming this unsent
				// generation between coalescing it and discarding it.
				existing.finalizeLocked()
			}
			return
		}
		// A response claimed the existing generation before its callback ran.
		// Leave that lifecycle response-owned and start another unsent chain.
		state.unsentRollbacks.Remove(typeURL)
	}
	if rollback.empty() {
		return
	}

	// Response rollback must outlive the context of the mutation which created
	// it. A later NACK remains actionable after that caller has timed out.
	lifecycle := c.newRollbackLifecycle(context.Background(), nodeID, typeURL, generation, rollback)
	registered := c.completionCbs.AddTypeGenerationWithRollback(generation, typeURL, nodeID, lifecycle)
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

// Revert restores caller-owned state after the enclosing transaction fails,
// or response-owned state after a NACK. Each resource's generation fences its
// revert; restoring its previous entry also restores the generation needed by
// an older rollback in a newest-first coalesced NACK chain.
func (lifecycle *rollbackLifecycle) Revert() error {
	c := lifecycle.cache
	tx := c.beginResourceTransaction(lifecycle.ctx, lifecycle.nodeID)
	resources, inverse, ok := lifecycle.takeRollbackLocked("revert")
	if !ok {
		tx.complete()
		return nil
	}

	state := tx.state
	var changes resourceChanges
	if resources == nil {
		changes = state.resourceRevertInverse(lifecycle.generation, inverse)
	} else {
		changes = state.resourceRevert(*resources)
	}
	if state != nil {
		if resources == nil {
			state.releaseInverseRollback(inverse, lifecycle.generation)
		} else {
			state.releaseRollback(*resources)
		}
	}
	if changes.empty() {
		var currentGeneration uint64
		if state != nil {
			currentGeneration = state.resourceGeneration
		}
		tx.complete()
		c.logger.Debug(
			"Skipping revert, affected resources have been superseded",
			logfields.NodeID, lifecycle.nodeID,
			logfields.XDSPushedGeneration, lifecycle.generation,
			logfields.XDSCurrentGeneration, currentGeneration,
		)
		return nil
	}

	c.logger.Debug("Reverting snapshot for node", logfields.NodeID, lifecycle.nodeID)
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	changedTypeURLs := changes.typeURLs()
	err := tx.updateResourceChangesLocked(changes, inverseResources{}, snapshotTypesChangedBy(changedTypeURLs), changedTypeURLs,
		nil, typeURLWaits{}, noRollbackTracking)
	tx.listenerChanges = committedListenerChanges(changes)
	tx.complete()
	if err != nil {
		c.logger.Error("Failed to revert snapshot",
			logfields.NodeID, lifecycle.nodeID,
			logfields.Error, err)
	}
	return nil
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

// generationForType returns the generation of the snapshot which currently
// represents typeURL. Eager publication makes it the same for every type.
func (state *nodeState) generationForType(typeURL typeurl.Index) uint64 {
	if state == nil {
		return 0
	}
	_ = typeURL
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

// generateSnapshotForUpdate is shared by every production mutation.
func (c *cacheImpl) generateSnapshotForUpdate(state *nodeState) (cache.ResourceSnapshot, error) {
	snapshot, err := c.generateSnapshotFromState(state)
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

// updateResourceChangesLocked commits one prepared mutation and publishes its
// snapshot before returning. Caller rollback tracking retains the inverse
// through publication; the lifecycle is created only after this succeeds.
// Caller must hold c.mutex; post-lock work is kept on tx.
func (tx *resourceTransaction) updateResourceChangesLocked(changes resourceChanges, inverse inverseResources, dirtyTypeURLs, changedTypeURLs typeurl.Set, wg *completion.WaitGroup, waits typeURLWaits, tracking rollbackTracking) error {
	c := tx.cache
	state := tx.state
	stateExisted := state != nil
	if state == nil {
		state = &nodeState{}
	}
	checkStrictConsistency := c.strictAdsMode && changes.affectsStrictConsistency()
	var strictChanges strictConsistencyChanges
	if checkStrictConsistency {
		var err error
		strictChanges, err = state.validateStrictConsistency(changes)
		if err != nil {
			tx.updateErr = fmt.Errorf("strict ADS cache mutation is inconsistent: %w", err)
			return tx.updateErr
		}
	}
	if !stateExisted {
		c.nodeStates[tx.nodeID] = state
		tx.state = state
	}
	oldResourceGeneration := state.resourceGeneration
	state.commitResourceMutation(changes)
	if checkStrictConsistency {
		state.strictRefs.apply(strictChanges, 1)
	}
	if tracking == callerAndResponseRollbackTracking {
		state.updateInverseRollbackOwners(inverse, tx.generation, 1)
	}
	completions, immediateCompletions := c.registerPrepublicationCompletions(
		tx.nodeID, wg, waits)
	completionTypeURLs := mergeTypeURLWaits(dirtyTypeURLs, waits)
	var rollbacks typeurl.Map[rollbackResources]
	if tracking != noRollbackTracking {
		rollbacks = state.mergePublicationRollbacks(rollbacks, changedTypeURLs, inverse, tx.generation, c.strictAdsMode)
	}
	finalized, err := c.publishSnapshotLocked(tx.ctx, tx.nodeID, snapshotPublication{
		generation:         tx.generation,
		completionTypeURLs: completionTypeURLs,
		rollbacks:          rollbacks,
	})
	deliveries := c.collectResponseDeliveriesLocked()
	if err != nil {
		if tracking == callerAndResponseRollbackTracking {
			state.releaseInverseRollback(inverse, tx.generation)
		}
		if !stateExisted {
			delete(c.nodeStates, tx.nodeID)
			tx.state = nil
		} else {
			// Prepared previous entries also recover failed rollback publications,
			// without allocating inverse maps or materializing a singleton.
			if !changes.empty() {
				change := changes.first
				state.resources[change.typeURL].commitEntry(change.name, change.previous)
			}
			for _, change := range changes.more {
				state.resources[change.typeURL].commitEntry(change.name, change.previous)
			}
			if checkStrictConsistency {
				state.strictRefs.apply(strictChanges, -1)
			}
			state.releaseRollbackSet(rollbacks)
			state.resourceGeneration = oldResourceGeneration
		}
	} else {
		state.resourceGeneration = tx.generation
		if tracking == responseRollbackTracking && changes.hasRemovals() {
			// Without a caller lifecycle, a removal tombstone is needed only
			// while cache-owned response rollback still references it. A
			// coalesced add/remove may leave no such rollback to release it.
			for typeURL := range changedTypeURLs.Members() {
				state.pruneInverseTombstones(typeURL, &state.resources[typeURL].entries, inverse, tx.generation)
			}
		}
	}
	tx.deliveries = deliveries
	tx.finalized = finalized
	tx.registeredCompletions.Merge(completions)
	tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
	tx.updateErr = err
	return err
}

// awaitCurrentVersionLocked registers no-op waits against the published
// snapshot. Caller holds c.mutex; callbacks are completed after unlocking.
func (tx *resourceTransaction) awaitCurrentVersionLocked(wg *completion.WaitGroup, waits typeURLWaits) error {
	c := tx.cache
	currentSnapshot, err := c.SnapshotCache.GetSnapshot(tx.nodeID)
	if err != nil {
		return fmt.Errorf("failed to get current snapshot for node %s: %w", tx.nodeID, err)
	}
	registered, immediateCompletions := c.registerGenerationCompletions(tx.nodeID, currentSnapshot, wg, waits)
	tx.registeredCompletions.Merge(registered)
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
			for watch := range watches.Members() {
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

func (c *cacheImpl) relayForLocked(responseChannel chan cache.Response) *watchRelay {
	if relay := c.watchRelays[responseChannel]; relay != nil {
		return relay
	}
	// Allow a full ADS response batch (one watch per supported type) plus an
	// immediate CreateWatch response to be queued before forwarding anything.
	// Keep at least the stream channel's capacity to avoid reducing its buffering.
	capacity := max(cap(responseChannel), int(typeurl.Count)+1)
	relay := &watchRelay{
		inner: make(chan cache.Response, capacity),
		outer: responseChannel,
	}
	c.watchRelays[responseChannel] = relay
	return relay
}

func (c *cacheImpl) addTrackedWatchLocked(request *cache.Request, typeURL typeurl.Index, responseChannel chan cache.Response) *trackedWatch {
	relay := c.relayForLocked(responseChannel)
	watch := &trackedWatch{
		nodeID:  request.GetNode().GetId(),
		typeURL: typeURL,
		request: request,
		relay:   relay,
	}
	state := c.openWatches[watch.nodeID]
	if state == nil {
		state = &nodeWatchState{}
		c.openWatches[watch.nodeID] = state
	}
	watches, _ := state.Get(watch.typeURL)
	watches.Insert(watch)
	// Sets are stored by value; persist the header when their representation
	// changes between an inline singleton and a map.
	state.Set(watch.typeURL, watches)
	relay.watches.Insert(watch)
	return watch
}

func (c *cacheImpl) removeTrackedWatchLocked(watch *trackedWatch) {
	if watch == nil {
		return
	}
	if state := c.openWatches[watch.nodeID]; state != nil {
		watches, exists := state.Get(watch.typeURL)
		if exists {
			watches.Remove(watch)
			if watches.Empty() {
				state.Remove(watch.typeURL)
			} else {
				state.Set(watch.typeURL, watches)
			}
		}
		if state.Empty() {
			delete(c.openWatches, watch.nodeID)
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
				responses = append(responses, response)
				var matched *trackedWatch
				for watch := range relay.watches.Members() {
					if watch.request == response.GetRequest() {
						matched = watch
						break
					}
				}
				if matched != nil {
					c.claimUnsentRollbackLocked(matched.nodeID, matched.typeURL)
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
	emptySnapshot, err := c.generateSnapshotForUpdate(&nodeState{})
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
	if request != nil && request.GetTypeUrl() == envoy_resource.SecretType && len(request.GetResourceNames()) == 0 {
		c.logger.Debug("Ignoring empty ADS SDS watch")
		return func() {}, nil
	}
	request = normalizeCustomWildcardRequest(request, sub)
	if request == nil || request.GetNode() == nil || sub == nil {
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
	state := c.nodeStates[nodeID]
	if state == nil {
		if err = c.ensureSnapshotForWatchLocked(nodeID); err != nil {
			deliveries := c.collectResponseDeliveriesLocked()
			c.mutex.Unlock()
			c.deliverResponses(deliveries)
			return nil, err
		}
	}
	// Register before calling go-control-plane: CreateWatch may immediately
	// queue a response rather than establish a deferred watch. Its relay keeps
	// that response buffered until we retire the watch and release the locks.
	watch := c.addTrackedWatchLocked(request, typeURL, respChan)
	watch.cancel, err = c.SnapshotCache.CreateWatch(request, sub, watch.relay.inner)
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
