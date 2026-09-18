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

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	controlplanelog "github.com/envoyproxy/go-control-plane/pkg/log"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"

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
	// nodeStates hold the private mutable desired resources and the names changed
	// since the last snapshot publication, together with protocol state retained
	// while the node has desired resources, rollback state, or an open stream.
	nodeStates map[string]*nodeState
	// go-control-plane exposes only total watch counts, so responses are relayed
	// through cache-owned channels to retire each TypeURL-indexed openWatches entry as
	// soon as it is consumed.
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

type stagedSnapshot struct {
	generation uint64
	// changedTypeURLs includes types whose published resources or aggregate
	// SotW versions may change. watchTypeURLs contains the directly mutated
	// types which can justify publication when Envoy has capacity for them.
	changedTypeURLs    typeurl.Set
	watchTypeURLs      typeurl.Set
	completionTypeURLs typeurl.Set
	rollbacks          typeurl.Map[rollbackResources]
}

type rollbackTracking uint8

const (
	noRollbackTracking                rollbackTracking = iota // response-driven reverts and test-only snapshot updates
	responseRollbackTracking                                  // cache-owned NACK rollback only
	callerAndResponseRollbackTracking                         // cache-owned NACK and caller-owned rollback
)

// nodeState separates the mutable cache-private desired state from the last
// immutable snapshot published to Envoy. Each resource type retains only the
// names touched since publication, allowing finalization to update the
// published go-control-plane maps without traversing the complete desired
// state.
type nodeState struct {
	// epoch is the wire-version namespace shared by every resource type for this
	// node. Each resource type retains the epoch reported by its first request,
	// allowing later TypeURL negotiations to avoid every namespace Envoy may
	// have retained from an earlier agent instance.
	epoch uint64
	// streams keeps protocol state alive across intervals with no desired
	// resources. Modes have separate slots because go-control-plane allocates
	// overlapping SotW and Delta stream IDs. Stream ID zero is never inserted
	// because it denotes a direct cache watch outside a go-control-plane stream
	// callback.
	streams [callbacks.StreamModeCount]set.Set[int64]
	// resourceGeneration identifies the latest desired state, while
	// snapshotGeneration identifies the state most recently published to Envoy.
	resourceGeneration uint64
	snapshotGeneration uint64
	// resources owns the current desired state, including generation-tagged
	// removal tombstones, and the sparse set of names which may differ from the
	// last published snapshot.
	resources cacheResources
	// strictRefs is allocated only for strict ADS nodes when a mutation first
	// touches LDS/RDS or CDS/EDS consistency. Nil means not yet indexed.
	strictRefs *strictReferenceCounts
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
	// generation identifies the latest desired state of this resource type.
	// It also advances when another resource type changes its subscription
	// dependencies, so SotW watches observe a new aggregate version.
	generation uint64
	// reportedEpoch is the greatest epoch parsed from this TypeURL's first
	// request. Retaining it lets a later TypeURL advance the shared node epoch
	// past namespaces Envoy retained from an earlier agent instance.
	reportedEpoch uint64
	// negotiatedEpoch is zero until the first request for this TypeURL has
	// negotiated the node epoch. A value different from nodeState.epoch means an
	// epoch rotation still needs to be reflected in the published snapshot.
	negotiatedEpoch uint64
}

// disposable reports whether nodeState contains neither desired/rollback state
// nor a stream which needs its negotiated epoch. Resource maps must be wholly
// empty: nil-resource tombstones still protect possible NACK rollback.
func (state *nodeState) disposable() bool {
	if state == nil {
		return true
	}
	// Desired resources are the overwhelmingly common reason for retaining a
	// node. Check resource maps first so finalizing a rollback can normally stop
	// after one or a few len(map) operations. Nil-resource tombstones count as
	// entries because they may still be needed by a later NACK rollback.
	for typeURL := range typeurl.Indices() {
		if len(state.resources[typeURL].entries) != 0 {
			return false
		}
	}
	if !state.streams[callbacks.StreamModeSotW].Empty() ||
		!state.streams[callbacks.StreamModeDelta].Empty() ||
		state.staged != nil ||
		!state.unsentRollbacks.Empty() || !state.rollbackOwners.Empty() {
		return false
	}
	for typeURL := range typeurl.Indices() {
		if !state.resources[typeURL].changed.Empty() {
			return false
		}
	}
	return true
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

// nodeWatchState indexes open watches by protocol mode and resource type.
// Each type can have multiple watches because several streams can subscribe
// for the same node. Index watch pointers, not requests: independent watches
// may share a request.
type nodeWatchState [callbacks.StreamModeCount]typeurl.Map[set.Set[*trackedWatch]]

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

type responseDeliveries struct {
	sotw []responseDelivery
}

func (deliveries *responseDeliveries) append(more responseDeliveries) {
	deliveries.sotw = append(deliveries.sotw, more.sotw...)
}

var _ Cache = &cacheImpl{}
var _ callbacks.StreamLifecycleHandler = (*cacheImpl)(nil)

// snapshotResourceGroup keeps the published resources together with the
// generation.
type snapshotResourceGroup struct {
	resources  cache.Resources
	generation uint64
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
var _ interface{ Consistent() error } = &ciliumSnapshot{}

func newCiliumSnapshot(resourceGroups typeurl.Slots[snapshotResourceGroup], epoch uint64) *ciliumSnapshot {
	for typeURL := range typeurl.Indices() {
		group := resourceGroups[typeURL]
		group.resources.Version = formatXDSVersion(epoch, group.generation)
		resourceGroups[typeURL] = group
	}
	return &ciliumSnapshot{
		resourceGroups: resourceGroups,
		epoch:          epoch,
	}
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

func (w *ciliumSnapshot) Consistent() error {
	if w == nil {
		return fmt.Errorf("nil snapshot")
	}

	var resourceGroups [cache_types.UnknownType]cache.Resources
	for typeURL := range typeurl.Indices() {
		resources := w.resourceGroups[typeURL].resources
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
	}
	for _, option := range options {
		option(c)
	}
	c.completionCbs = callbacks.NewCompletionCallbacks(logger, c)
	return c
}

func formatXDSVersion(epoch, generation uint64) string {
	return "e" + strconv.FormatUint(epoch, 10) + ":g" + strconv.FormatUint(generation, 10)
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

// selectEpochLocked negotiates the shared node epoch when this TypeURL is
// first requested. An already negotiated TypeURL reporting the current epoch
// is ordinary stream continuity, not a collision. Caller must hold c.mutex.
func (state *nodeState) selectEpochLocked(typeURL typeurl.Index, versions iter.Seq[string]) (epochChanged bool) {
	if state.resources[typeURL].negotiatedEpoch != 0 {
		return false
	}
	var reported set.Set[uint64]
	for version := range versions {
		if epoch, ok := parseXDSEpoch(version); ok {
			reported.Insert(epoch)
			state.resources[typeURL].reportedEpoch = max(state.resources[typeURL].reportedEpoch, epoch)
		}
	}
	previous := state.epoch
	if state.epoch == 0 {
		for state.epoch = 1; reported.Has(state.epoch); state.epoch++ {
		}
	} else if reported.Has(state.epoch) {
		// Once one TypeURL has already selected the shared node epoch, move past
		// every epoch retained from earlier first requests.
		for index := range typeurl.Indices() {
			state.epoch = max(state.epoch, state.resources[index].reportedEpoch)
		}
		state.epoch++
	}
	return state.epoch != previous
}

func singleVersion(version string) iter.Seq[string] {
	return func(yield func(string) bool) {
		yield(version)
	}
}

// commitEpochNegotiation records that typeURL and every previously negotiated
// resource type are represented by the snapshot bound to the current node
// epoch. Caller must hold c.mutex after successful snapshot publication.
func (state *nodeState) commitEpochNegotiation(typeURL typeurl.Index) {
	for index := range typeurl.Indices() {
		if index == typeURL || state.resources[index].negotiatedEpoch != 0 {
			state.resources[index].negotiatedEpoch = state.epoch
		}
	}
}

func incrementalSnapshotTypeURLs(changedTypeURLs typeurl.Set) (typeurl.Set, bool) {
	if !changedTypeURLs.Known() {
		return typeurl.Set{}, false
	}
	regenerate := changedTypeURLs
	if changedTypeURLs.Has(typeurl.Cluster) {
		regenerate.Insert(typeurl.Endpoint)
	}

	return regenerate, true
}

func canGenerateSnapshotIncrementally(previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (*ciliumSnapshot, typeurl.Set, bool) {
	previousSnapshot, ok := previous.(*ciliumSnapshot)
	if !ok || previousSnapshot == nil {
		return nil, typeurl.Set{}, false
	}
	regenerate, ok := incrementalSnapshotTypeURLs(changedTypeURLs)
	return previousSnapshot, regenerate, ok
}

func resourceGroupFromEntries(resources map[string]resourceEntry) cache.Resources {
	items := make(map[string]cache_types.ResourceWithTTL, len(resources))
	for name, entry := range resources {
		if entry.resource == nil {
			continue
		}
		items[name] = cache_types.ResourceWithTTL{Resource: entry.resource}
	}
	if len(items) == 0 {
		items = nil
	}
	return cache.Resources{Items: items}
}

func updateResourceEntries(resources map[string]resourceEntry, changed set.Set[string], previous cache.Resources) cache.Resources {
	items := previous.Items
	itemsCloned := false
	cloneItems := func() {
		if itemsCloned {
			return
		}
		items = maps.Clone(items)
		itemsCloned = true
	}
	for name := range changed.Members() {
		entry := resources[name]
		resource := entry.resource
		previousItem, resourceExists := items[name]
		if resource == nil {
			if !resourceExists {
				continue
			}
			cloneItems()
			delete(items, name)
			continue
		}
		if resourceExists && previousItem.Resource == resource {
			continue
		}
		if !resourceExists || previousItem.Resource != resource {
			cloneItems()
			if items == nil {
				items = make(map[string]cache_types.ResourceWithTTL)
			}
			items[name] = cache_types.ResourceWithTTL{Resource: resource}
		}
	}
	return cache.Resources{Items: items}
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

// desiredEndpoint projects the desired endpoint state into a snapshot. It
// synthesizes an empty assignment for an EDS cluster without mutating the
// cache's desired resources.
func (resources *cacheResources) desiredEndpoint(name string) (resourceEntry, bool) {
	if entry := resources[typeurl.Endpoint].entries[name]; entry.resource != nil {
		// Skip wildcard :* endpoints that have no matching cluster,
		// as they cause snapshot inconsistency (EDS count > CDS references).
		// These are generated for backward compatibility with the old per-type
		// xDS caches but are not needed in the ADS snapshot.
		if _, hasCluster := currentResource(resources[typeurl.Cluster].entries, name); !hasCluster && strings.HasSuffix(name, ":*") {
			return resourceEntry{}, false
		}
		return entry, true
	}
	for clusterName, entry := range resources[typeurl.Cluster].entries {
		if entry.resource != nil && clusterEndpointName(clusterName, typedResource[*envoy_config_cluster.Cluster](entry.resource)) == name {
			return resourceEntry{
				resource:   &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name},
				generation: entry.generation,
			}, true
		}
	}
	return resourceEntry{}, false
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
	previousClusters := previous.resourceGroups[typeurl.Cluster].resources.Items
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

func resourceGroupFromLookup(names map[string]struct{}, lookup func(string) (resourceEntry, bool)) cache.Resources {
	items := make(map[string]cache_types.ResourceWithTTL, len(names))
	for name := range names {
		entry, exists := lookup(name)
		if !exists {
			continue
		}
		items[name] = cache_types.ResourceWithTTL{Resource: entry.resource}
	}
	if len(items) == 0 {
		items = nil
	}
	return cache.Resources{Items: items}
}

func updateResourceLookup(changed set.Set[string], lookup func(string) (resourceEntry, bool), previous cache.Resources) cache.Resources {
	items := previous.Items
	itemsCloned := false
	cloneItems := func() {
		if itemsCloned {
			return
		}
		items = maps.Clone(items)
		itemsCloned = true
	}
	for name := range changed.Members() {
		entry, exists := lookup(name)
		previousItem, resourceExists := items[name]
		if !exists {
			if !resourceExists {
				continue
			}
			cloneItems()
			delete(items, name)
			continue
		}
		if resourceExists && previousItem.Resource == entry.resource {
			continue
		}
		if !resourceExists || previousItem.Resource != entry.resource {
			cloneItems()
			if items == nil {
				items = make(map[string]cache_types.ResourceWithTTL)
			}
			items[name] = cache_types.ResourceWithTTL{Resource: entry.resource}
		}
	}
	return cache.Resources{Items: items}
}

func (c *cacheImpl) generateSnapshotFromState(state *nodeState) (cache.ResourceSnapshot, error) {
	var resourceGroups typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Indices() {
		var group cache.Resources
		typeState := &state.resources[typeURL]
		generation := typeState.generation
		if typeURL == typeurl.Endpoint {
			group = resourceGroupFromLookup(state.resources.endpointResourceNames(), state.resources.desiredEndpoint)
		} else {
			group = resourceGroupFromEntries(typeState.entries)
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources:  group,
			generation: generation,
		}
	}
	return newCiliumSnapshot(resourceGroups, state.epoch), nil
}

// clusterEndpointsNeedingReplay identifies an EDS name already subscribed by
// an old Cluster when a changed or newly added Cluster starts using it. Envoy
// can warm that Cluster only after another EDS response, but will not send a
// new subscription if the name is already in its EDS subscription set.
func (state *nodeState) clusterEndpointsNeedingReplay(previous *ciliumSnapshot) set.Set[string] {
	var endpoints set.Set[string]
	oldClusters := previous.resourceGroups[typeurl.Cluster].resources.Items
	for name := range state.resources[typeurl.Cluster].changed.Members() {
		current := state.resources[typeurl.Cluster].entries[name].resource
		if current == nil {
			continue
		}
		if old, exists := oldClusters[name]; exists && old.Resource == current {
			continue
		}
		endpointName := clusterEndpointName(name, current.(*envoy_config_cluster.Cluster))
		if endpointName == "" {
			continue
		}
		for oldName, old := range oldClusters {
			if clusterEndpointName(oldName, old.Resource.(*envoy_config_cluster.Cluster)) == endpointName {
				endpoints.Insert(endpointName)
				break
			}
		}
	}
	return endpoints
}

func (c *cacheImpl) generateSnapshotFromStateIncrementally(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error) {
	previousSnapshot, regenerate, ok := canGenerateSnapshotIncrementally(previous, changedTypeURLs)
	if !ok {
		return c.generateSnapshotFromState(state)
	}
	if regenerate.Empty() {
		return previousSnapshot, nil
	}

	// Envoy needs a fresh EDS response to warm a Cluster that uses an EDS name
	// already subscribed by an earlier Cluster, even when the CLA is unchanged.
	// A genuinely new EDS name is instead answered by its new subscription.
	resourceGroups := previousSnapshot.resourceGroups
	replayedEndpoints := state.clusterEndpointsNeedingReplay(previousSnapshot)
	for typeURL := range regenerate.Members() {
		previousGroup := previousSnapshot.resourceGroups[typeURL]
		var group cache.Resources
		typeState := &state.resources[typeURL]
		generation := typeState.generation
		if typeURL == typeurl.Endpoint && !replayedEndpoints.Empty() {
			generation = max(generation, state.resources[typeurl.Cluster].generation)
		}
		if typeURL == typeurl.Endpoint {
			group = updateResourceLookup(state.changedEndpointResourceNames(previousSnapshot), state.resources.desiredEndpoint, previousGroup.resources)
		} else {
			group = updateResourceEntries(typeState.entries, typeState.changed, previousGroup.resources)
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources:  group,
			generation: generation,
		}
	}
	return newCiliumSnapshot(resourceGroups, state.epoch), nil
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

	generation            uint64
	deliveries            responseDeliveries
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

func (c *cacheImpl) registerStagedGenerationCompletions(nodeID string, wg *completion.WaitGroup, waits typeURLWaits) (set.Set[*completion.Completion], []immediateCompletion) {
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
		if rollback.empty() {
			base.Remove(typeURL)
		} else {
			base.Set(typeURL, rollback)
		}
	}
	return base
}

// clone copies every map in a staged rollback. In strict ADS mode, a rollback
// slot can also contain resources of a companion TypeURL.
func (rollback rollbackResources) clone() rollbackResources {
	for typeURL := range typeurl.Indices() {
		rollback[typeURL] = maps.Clone(rollback[typeURL])
	}
	return rollback
}

func cloneStagedRollbacks(rollbacks typeurl.Map[rollbackResources]) typeurl.Map[rollbackResources] {
	var cloned typeurl.Map[rollbackResources]
	for typeURL, rollback := range rollbacks.All() {
		cloned.Set(typeURL, rollback.clone())
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

	oldSnapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	newSnapshot, err := c.generateSnapshotForUpdate(state, oldSnapshot, staged.changedTypeURLs)
	if err != nil {
		return false, nil, err
	}
	return c.installStagedSnapshotLocked(ctx, nodeID, state, staged, oldSnapshot, newSnapshot)
}

// installStagedSnapshotLocked publishes a constructed snapshot and resolves its
// staged completions. The caller must hold c.mutex.
func (c *cacheImpl) installStagedSnapshotLocked(ctx context.Context, nodeID string, state *nodeState, staged *stagedSnapshot, oldSnapshot, newSnapshot cache.ResourceSnapshot) (bool, []finalizedCompletion, error) {
	err := c.SnapshotCache.SetSnapshot(callbacks.WithSnapshotGeneration(ctx, staged.generation), nodeID, newSnapshot)
	if err != nil {
		// SnapshotCache stores the snapshot before delivering watch responses. A
		// canceled delivery may therefore return an error after publication has
		// committed; keep generation state in that case.
		currentSnapshot, getErr := c.SnapshotCache.GetSnapshot(nodeID)
		committed := getErr == nil && !c.areDifferentSnapshots(currentSnapshot, newSnapshot)
		if !committed {
			return false, nil, err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}
	// Watch responses remain in Cilium's relays until after this publication
	// finishes, so expose the snapshot to callbacks only once it is committed.
	c.completionCbs.SetPublishedSnapshot(nodeID, staged.generation, newSnapshot)

	state.staged = nil
	state.snapshotGeneration = staged.generation
	if published, ok := newSnapshot.(*ciliumSnapshot); ok {
		for typeURL := range typeurl.Indices() {
			state.resources[typeURL].generation = published.resourceGroups[typeURL].generation
		}
	}
	for typeURL := range typeurl.Indices() {
		state.resources[typeURL].changed = set.Set[string]{}
	}
	// Retain rollback only for resource types whose published version changed.
	// Until go-control-plane actually produces a response, repeated published
	// generations are coalesced into one rollback per type. An older mutation
	// without a WaitGroup may precede a tracked mutation in the same eventual
	// response, and a NACK must restore the state before that whole batch.
	for typeURL, rollback := range staged.rollbacks.All() {
		if rollback.empty() {
			continue
		}
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

func (state *nodeState) commitResourceMutation(changes resourceChanges, generation uint64) {
	commit := func(change resourceChange) {
		typeState := &state.resources[change.typeURL]
		typeState.commitEntry(change.name, change.next)
		// Aggregate xDS versions advance even when a revert restores an older
		// resource entry and its original generation.
		typeState.generation = generation
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

func (state *nodeState) reconcileChangedResourceNames(changes resourceChanges, published cache.ResourceSnapshot) {
	reconcile := func(change resourceChange) {
		resources := &state.resources[change.typeURL]
		resource := resources.entries[change.name].resource
		var publishedResources map[string]cache_types.ResourceWithTTL
		if published != nil {
			publishedResources = published.GetResourcesAndTTL(change.typeURL.URL())
		}
		publishedResource, publishedExists := publishedResources[change.name]
		if resource == nil {
			if !publishedExists {
				resources.changed.Remove(change.name)
			}
			return
		}
		if publishedExists &&
			(publishedResource.Resource == resource || xds.ResourceEqual(publishedResource.Resource, resource)) {
			resources.changed.Remove(change.name)
		}
	}
	if !changes.empty() {
		reconcile(changes.first)
	}
	for _, change := range changes.more {
		reconcile(change)
	}
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
	state := lifecycle.cache.nodeStates[lifecycle.nodeID]
	if state != nil {
		if resources == nil {
			state.releaseInverseRollback(inverse, lifecycle.generation)
		} else {
			state.releaseRollback(*resources)
		}
		// A node with any Listener entry cannot be discarded. Keep this guard at
		// the hot finalize call site so the normal agent case avoids the broader
		// nodeState disposal check. Removal tombstones intentionally count as
		// entries until their final rollback owner releases them.
		if len(state.resources[typeurl.Listener].entries) != 0 {
			return
		}
	}
	lifecycle.cache.maybeDeleteNodeStateLocked(lifecycle.nodeID, true)
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

// generateSnapshotForUpdate constructs an incremental snapshot from staged
// resources when a watch can consume them.
func (c *cacheImpl) generateSnapshotForUpdate(state *nodeState, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set) (cache.ResourceSnapshot, error) {
	snapshot, err := c.generateSnapshotFromStateIncrementally(state, previous, changedTypeURLs)
	if err != nil {
		return nil, err
	}
	// Mutation-time validation maintains the strict ADS invariant. The full
	// snapshot check is a projection invariant check for agent debug mode.
	if c.strictAdsMode && c.logger != nil && c.logger.Enabled(context.Background(), slog.LevelDebug) {
		if err := CheckSnapshotConsistency(snapshot); err != nil {
			return nil, fmt.Errorf("generated ADS snapshot is inconsistent: %w", err)
		}
	}
	return snapshot, nil
}

// updateResourceChangesLocked commits one prepared mutation and optionally
// finalizes it for an open watch. Caller rollback tracking retains the inverse
// until the caller lifecycle is created after successful staging or publication.
// Caller must hold the cache mutex; post-lock work is accumulated on tx.
func (tx *resourceTransaction) updateResourceChangesLocked(changes resourceChanges, inverse inverseResources, dirtyTypeURLs, watchTypeURLs typeurl.Set, wg *completion.WaitGroup, waits typeURLWaits, tracking rollbackTracking) error {
	c := tx.cache
	// Snapshot dependencies can make dirtyTypeURLs broader than the mutation.
	// Responses are ACKed or NACKed independently by TypeURL, so retain rollback
	// state only for resource types directly changed by this transaction.
	rollbackTypeURLs := watchTypeURLs

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

		// The first desired state must establish a complete baseline for whichever
		// supported resource type Envoy requests first.
		watchTypeURLs = snapshotTypesChangedBy(typeurl.Set{})
	}
	oldResourceGeneration := state.resourceGeneration
	var oldTypeGenerations typeurl.Slots[uint64]
	for typeURL := range typeurl.Indices() {
		oldTypeGenerations[typeURL] = state.resources[typeURL].generation
	}
	state.commitResourceMutation(changes, tx.generation)
	if checkStrictConsistency {
		state.strictRefs.apply(strictChanges, 1)
	}
	if tracking == callerAndResponseRollbackTracking {
		state.updateInverseRollbackOwners(inverse, tx.generation, 1)
	}
	completions, immediateCompletions := c.registerStagedGenerationCompletions(
		tx.nodeID, wg, waits)
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
	if tracking != noRollbackTracking {
		rollbacks = state.mergeStagedRollbacks(rollbacks, rollbackTypeURLs, inverse, tx.generation, c.strictAdsMode)
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
	}
	state.staged = staged

	var finalized []finalizedCompletion
	var err error
	if willFinalize {
		_, finalized, err = c.finalizeStagedSnapshotLocked(tx.ctx, tx.nodeID)
	}
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
			// Re-establish the old stage ownership before releasing the failed
			// replacement so shared tombstones remain continuously guarded.
			if oldStaged != nil {
				state.acquireRollbackSet(oldStagedValue.rollbacks)
			}
			state.releaseRollbackSet(rollbacks)
			published, _ := c.SnapshotCache.GetSnapshot(tx.nodeID)
			state.reconcileChangedResourceNames(changes, published)
			state.resourceGeneration = oldResourceGeneration
			for typeURL := range typeurl.Indices() {
				state.resources[typeURL].generation = oldTypeGenerations[typeURL]
			}
			if oldStaged == nil {
				state.staged = nil
			} else {
				*oldStaged = oldStagedValue
				state.staged = oldStaged
			}
		}
	} else {
		state.resourceGeneration = tx.generation
		if tracking == responseRollbackTracking && changes.hasRemovals() {
			// Without a caller lifecycle, a removal tombstone is needed only
			// while cache-owned response rollback still references it. A
			// coalesced add/remove may leave no such rollback to release it.
			for typeURL := range rollbackTypeURLs.Members() {
				state.pruneInverseTombstones(typeURL, &state.resources[typeURL].entries, inverse, tx.generation)
			}
		}
	}
	tx.deliveries = deliveries
	tx.finalized = finalized
	tx.registeredCompletions.Merge(completions)
	tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
	tx.updateErr = err
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
		if !publishedWaits.Empty() {
			currentSnapshot, err := c.SnapshotCache.GetSnapshot(tx.nodeID)
			if err != nil {
				return fmt.Errorf("failed to get current snapshot for node %s: %w", tx.nodeID, err)
			}
			registered, publishedImmediate := c.registerGenerationCompletions(
				tx.nodeID, currentSnapshot, wg, publishedWaits)
			tx.registeredCompletions.Merge(registered)
			tx.immediateCompletions = append(tx.immediateCompletions, publishedImmediate...)
		}

		if !stagedWaits.Empty() {
			registered, immediateCompletions := c.registerStagedGenerationCompletions(
				tx.nodeID, wg, stagedWaits)
			tx.registeredCompletions.Merge(registered)
			tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
		}
		return nil
	}

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
	var cancels []func()
	if watchesByMode := c.openWatches[nodeID]; watchesByMode != nil {
		for mode := range callbacks.StreamModeCount {
			for _, watches := range watchesByMode[mode].All() {
				for watch := range watches.Members() {
					if watch.cancel != nil {
						cancels = append(cancels, watch.cancel)
					}
					c.removeTrackedWatchLocked(watch)
				}
			}
		}
	}
	if state := c.nodeStates[nodeID]; state != nil {
		var reported typeurl.Slots[uint64]
		var negotiated typeurl.Slots[uint64]
		for typeURL := range typeurl.Indices() {
			reported[typeURL] = state.resources[typeURL].reportedEpoch
			negotiated[typeURL] = state.resources[typeURL].negotiatedEpoch
		}
		epoch, streams := state.epoch, state.streams
		*state = nodeState{
			epoch:   epoch,
			streams: streams,
		}
		for typeURL := range typeurl.Indices() {
			state.resources[typeURL].reportedEpoch = reported[typeURL]
			state.resources[typeURL].negotiatedEpoch = negotiated[typeURL]
		}
	}
	c.maybeDeleteNodeStateLocked(nodeID, false)
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

func (c *cacheImpl) maybeDeleteNodeStateLocked(nodeID string, clearSnapshot bool) {
	state := c.nodeStates[nodeID]
	if state == nil || !state.disposable() {
		return
	}
	delete(c.nodeStates, nodeID)
	if clearSnapshot {
		c.SnapshotCache.ClearSnapshot(nodeID)
	}
	c.completionCbs.SetPublishedSnapshot(nodeID, 0, nil)
}

// StreamStarted implements callbacks.StreamLifecycleHandler. Protocol modes
// have separate stream-ID spaces, so mode selects the corresponding slot.
func (c *cacheImpl) StreamStarted(streamID int64, nodeID string, mode callbacks.StreamMode) {
	if mode >= callbacks.StreamModeCount {
		return
	}
	c.mutex.Lock()
	state := c.nodeStates[nodeID]
	if state == nil {
		state = &nodeState{}
		c.nodeStates[nodeID] = state
	}
	state.streams[mode].Insert(streamID)
	c.mutex.Unlock()
}

// StreamClosed implements callbacks.StreamLifecycleHandler.
func (c *cacheImpl) StreamClosed(streamID int64, nodeID string, mode callbacks.StreamMode) {
	if mode >= callbacks.StreamModeCount {
		return
	}
	c.mutex.Lock()
	state := c.nodeStates[nodeID]
	if state != nil {
		state.streams[mode].Remove(streamID)
	}
	c.maybeDeleteNodeStateLocked(nodeID, true)
	c.mutex.Unlock()
}

func (c *cacheImpl) hasOpenWatchLocked(nodeID string, typeURLs typeurl.Set) bool {
	state := c.openWatches[nodeID]
	if state == nil {
		return false
	}
	for typeURL := range typeURLs.Members() {
		for mode := range callbacks.StreamModeCount {
			watches, _ := state[mode].Get(typeURL)
			if !watches.Empty() {
				return true
			}
		}
	}
	return false
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

func (c *cacheImpl) indexTrackedWatchLocked(watch *trackedWatch) {
	state := c.openWatches[watch.nodeID]
	if state == nil {
		state = &nodeWatchState{}
		c.openWatches[watch.nodeID] = state
	}
	mode := callbacks.StreamModeSotW
	watches, _ := state[mode].Get(watch.typeURL)
	watches.Insert(watch)
	// Sets are stored by value; persist the header when their representation
	// changes between an inline singleton and a map.
	state[mode].Set(watch.typeURL, watches)
}

func (c *cacheImpl) addTrackedWatchLocked(request *cache.Request, typeURL typeurl.Index, responseChannel chan cache.Response) *trackedWatch {
	relay := c.relayForLocked(responseChannel)
	watch := &trackedWatch{
		nodeID:  request.GetNode().GetId(),
		typeURL: typeURL,
		request: request,
		relay:   relay,
	}
	c.indexTrackedWatchLocked(watch)
	relay.watches.Insert(watch)
	return watch
}

func (c *cacheImpl) removeTrackedWatchLocked(watch *trackedWatch) {
	if watch == nil {
		return
	}
	if state := c.openWatches[watch.nodeID]; state != nil {
		mode := callbacks.StreamModeSotW
		watches, exists := state[mode].Get(watch.typeURL)
		if exists {
			watches.Remove(watch)
			if watches.Empty() {
				state[mode].Remove(watch.typeURL)
			} else {
				state[mode].Set(watch.typeURL, watches)
			}
		}
		if state[callbacks.StreamModeSotW].Empty() && state[callbacks.StreamModeDelta].Empty() {
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
func (c *cacheImpl) collectResponseDeliveriesLocked() responseDeliveries {
	var deliveries responseDeliveries
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
					deliveries.sotw = append(deliveries.sotw, responseDelivery{
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
func (c *cacheImpl) deliverResponses(deliveries responseDeliveries) {
	for _, delivery := range deliveries.sotw {
		// go-control-plane's non-strict ADS cache iterates watches in map order.
		// Preserve ADS dependency order before forwarding a coalesced batch to
		// the stream, without enabling its strict named-request hold.
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

// ensureSnapshotForWatchLocked establishes an authoritative empty snapshot for
// a node which has not produced any desired resources since agent startup.
// The node state retains the epoch negotiated by its streams even when its
// desired resources are empty. Caller must hold mutex.
func (c *cacheImpl) ensureSnapshotForWatchLocked(nodeID string) error {
	if _, err := c.SnapshotCache.GetSnapshot(nodeID); err == nil {
		return nil
	}
	state := c.nodeStates[nodeID]
	if state == nil {
		state = &nodeState{}
		c.nodeStates[nodeID] = state
	}
	emptySnapshot, err := c.generateSnapshotForUpdate(state, nil, typeurl.Set{})
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

func (c *cacheImpl) prepareLiveSnapshotLocked(nodeID string, typeURL typeurl.Index) ([]finalizedCompletion, error) {
	state := c.nodeStates[nodeID]
	if state == nil {
		return nil, c.ensureSnapshotForWatchLocked(nodeID)
	}
	if state.staged != nil && state.staged.watchTypeURLs.Has(typeURL) {
		_, finalized, err := c.finalizeStagedSnapshotLocked(context.Background(), nodeID)
		return finalized, err
	}

	// A later TypeURL may force the shared node epoch to rotate. Rebind only the
	// protocol view of the already-published snapshot. Rebuilding from desired
	// state here could accidentally publish unrelated staged changes.
	current, err := c.SnapshotCache.GetSnapshot(nodeID)
	if err != nil {
		return nil, c.ensureSnapshotForWatchLocked(nodeID)
	}
	currentSnapshot, ok := current.(*ciliumSnapshot)
	if ok {
		if currentSnapshot.epoch == state.epoch {
			return nil, nil
		}
		// Publish a new immutable protocol view when the shared epoch changes.
		rebuilt := currentSnapshot.withEpoch(state.epoch)
		c.completionCbs.SetPublishedSnapshot(nodeID, state.snapshotGeneration, rebuilt)
		if err := c.SnapshotCache.SetSnapshot(
			callbacks.WithSnapshotGeneration(context.Background(), state.snapshotGeneration),
			nodeID,
			rebuilt,
		); err != nil {
			c.completionCbs.SetPublishedSnapshot(nodeID, state.snapshotGeneration, current)
			return nil, err
		}
		return nil, nil
	}

	rebuilt, err := c.generateSnapshotFromState(state)
	if err != nil {
		return nil, err
	}
	c.completionCbs.SetPublishedSnapshot(nodeID, state.snapshotGeneration, rebuilt)
	if err := c.SnapshotCache.SetSnapshot(
		callbacks.WithSnapshotGeneration(context.Background(), state.snapshotGeneration),
		nodeID,
		rebuilt,
	); err != nil {
		c.completionCbs.SetPublishedSnapshot(nodeID, state.snapshotGeneration, current)
		return nil, err
	}
	return nil, nil
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
		state = &nodeState{}
		c.nodeStates[nodeID] = state
	}
	state.selectEpochLocked(typeURL, singleVersion(request.GetVersionInfo()))
	var finalized []finalizedCompletion
	deliveries := c.collectResponseDeliveriesLocked()
	finalized, err = c.prepareLiveSnapshotLocked(nodeID, typeURL)
	if err != nil {
		deliveries.append(c.collectResponseDeliveriesLocked())
		c.maybeDeleteNodeStateLocked(nodeID, false)
		c.mutex.Unlock()
		c.deliverResponses(deliveries)
		c.completeFinalized(nodeID, finalized)
		return nil, err
	}
	state.commitEpochNegotiation(typeURL)

	// Register before calling go-control-plane: CreateWatch may immediately
	// queue a response rather than establish a deferred watch. Its relay keeps
	// that response buffered until we retire the watch and release the locks.
	watch := c.addTrackedWatchLocked(request, typeURL, respChan)
	watch.cancel, err = c.SnapshotCache.CreateWatch(request, sub, watch.relay.inner)
	if err != nil {
		c.removeTrackedWatchLocked(watch)
		c.maybeDeleteNodeStateLocked(nodeID, false)
	}
	deliveries.append(c.collectResponseDeliveriesLocked())
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	c.completeFinalized(nodeID, finalized)
	if err != nil {
		return nil, err
	}
	return func() { c.cancelTrackedWatch(watch) }, nil
}

func (c *cacheImpl) CreateDeltaWatch(request *cache.DeltaRequest, sub cache.Subscription, respChan chan cache.DeltaResponse) (cancel func(), err error) {
	return c.SnapshotCache.CreateDeltaWatch(request, sub, respChan)
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
