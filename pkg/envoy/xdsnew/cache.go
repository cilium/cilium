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

type RevertFunc = callbacks.RevertFunc
type FinalizeFunc = callbacks.FinalizeFunc

// TypeURLCallbacks stores optional completion callbacks for supported resource
// types without allocating a string-keyed map.
type TypeURLCallbacks = typeurl.Map[func(error)]

// NewTypeURLCallbacks returns an explicitly initialized empty callback set.
// This differs from the zero value, which asks ApplyResources to infer the
// default Listener ACK wait when a listener is mutated.
func NewTypeURLCallbacks() TypeURLCallbacks {
	return typeurl.NewMap[func(error)]()
}

// ResourceMutations is a sparse resource transaction. Unchanged resource maps
// remain nil. Keeping the Resources values inline lets callers keep the sparse
// headers on their stack; only maps referenced by a transaction can escape.
type ResourceMutations struct {
	Removed  xds.Resources
	Upserted xds.Resources
}

// ListenerChange describes one committed listener transition. Previous is nil
// for an insertion and Current is nil for a removal. Resources are immutable
// cache-owned protobufs.
type ListenerChange struct {
	Name     string
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
	// On change it returns caller-owned revert and finalize functions. Exactly
	// one must eventually be called; cache-owned NACK rollback remains live
	// independently until the response is accepted or rejected.
	ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (bool, RevertFunc, FinalizeFunc, error)
	// Typed single-resource updates compare only the named resource and build a
	// sparse mutation only after detecting an actual semantic change.
	UpsertListener(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error)
	RemoveListener(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error)
	UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error)
	RemoveNetworkPolicy(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error)
	UpsertNetworkPolicyHosts(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (bool, RevertFunc, FinalizeFunc, error)
	RemoveNetworkPolicyHosts(ctx context.Context, nodeID, name string) (bool, RevertFunc, FinalizeFunc, error)
	// GetResource returns one cache-owned immutable resource without
	// materializing the complete desired resource maps.
	GetResource(nodeID string, typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool)
	// Resource iterators expose cache-owned immutable resources without
	// constructing xds.Resources or leaking the mutable internal maps. Iteration
	// holds the cache read lock, so loop bodies must not call back into the cache.
	Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener]
	Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration]
	NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy]
	// SetListenerObserver sets the single observer for committed listener
	// changes on one node. It must be called before the cache is used; a later
	// call logs a warning and replaces the observer.
	// lockedCallback runs synchronously under the cache mutation lock and
	// therefore must not call back into the cache or block. Returning true
	// requests unlockedCallback after the transaction releases the lock.
	SetListenerObserver(nodeID string, lockedCallback func(changes []ListenerChange) bool, unlockedCallback func())
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
}

type listenerObserver struct {
	nodeID           string
	lockedCallback   func(changes []ListenerChange) bool
	unlockedCallback func()
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
	// listenerObserver observes listener transitions for one node. Its locked
	// callback participates in cache commit order; its follow-up runs unlocked.
	listenerObserver listenerObserver
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
// immutable snapshot published to Envoy. changed retains only the names
// touched since publication, allowing finalization to update the published
// go-control-plane maps without traversing the complete desired state.
type nodeState struct {
	// resourceGeneration identifies the latest desired state, while
	// snapshotGeneration identifies the state most recently published to Envoy.
	resourceGeneration uint64
	snapshotGeneration uint64
	// resources owns the current desired state, including generation-tagged
	// removal tombstones. changed is a sparse set of names which may differ from
	// the last published snapshot.
	resources cacheResources
	changed   changedResourceNames
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
type resourceEntry[V comparable] struct {
	resource   V
	generation uint64
}

// cacheResources is the cache-private, generation-aware counterpart of
// xds.Resources. It deliberately excludes PortAllocationCallbacks, which are
// server-side listener bookkeeping rather than xDS resources.
type cacheResources struct {
	listeners          map[string]resourceEntry[*envoy_config_listener.Listener]
	routes             map[string]resourceEntry[*envoy_config_route.RouteConfiguration]
	clusters           map[string]resourceEntry[*envoy_config_cluster.Cluster]
	endpoints          map[string]resourceEntry[*envoy_config_endpoint.ClusterLoadAssignment]
	secrets            map[string]resourceEntry[*envoy_config_tls.Secret]
	networkPolicies    map[string]resourceEntry[*cilium.NetworkPolicy]
	networkPolicyHosts map[string]resourceEntry[*cilium.NetworkPolicyHosts]
}

// changedResourceNames mirrors cacheResources without duplicating resource
// values. These sets are retained until the desired state has been published
// successfully, and are also the natural input for future Delta ADS updates.
type changedResourceNames struct {
	listeners          set.Set[string]
	routes             set.Set[string]
	clusters           set.Set[string]
	endpoints          set.Set[string]
	secrets            set.Set[string]
	networkPolicies    set.Set[string]
	networkPolicyHosts set.Set[string]
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

type rollbackEntry[V comparable] struct {
	previous           resourceEntry[V]
	expectedGeneration uint64
}

type rollbackResources struct {
	listeners          map[string]rollbackEntry[*envoy_config_listener.Listener]
	routes             map[string]rollbackEntry[*envoy_config_route.RouteConfiguration]
	clusters           map[string]rollbackEntry[*envoy_config_cluster.Cluster]
	endpoints          map[string]rollbackEntry[*envoy_config_endpoint.ClusterLoadAssignment]
	secrets            map[string]rollbackEntry[*envoy_config_tls.Secret]
	networkPolicies    map[string]rollbackEntry[*cilium.NetworkPolicy]
	networkPolicyHosts map[string]rollbackEntry[*cilium.NetworkPolicyHosts]
}

type rollbackLifecycle struct {
	cache      *cacheImpl
	ctx        context.Context
	nodeID     string
	typeURL    typeurl.Index
	generation uint64
	resources  *rollbackResources
	inverse    cacheResources
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
	return controlplanelog.LoggerFuncs{
		DebugFunc: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		},
		InfoFunc: func(format string, args ...any) {
			// Consider using Debug here if Info is too chatty
			logger.Info(fmt.Sprintf(format, args...))
		},
		WarnFunc: func(format string, args ...any) {
			logger.Warn(fmt.Sprintf(format, args...))
		},
		ErrorFunc: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...))
		},
	}
}

func NewCache(logger *slog.Logger, strictAdsMode bool) Cache {
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

func (c *cacheImpl) getVersion(resources *xds.Resources) string {
	encodedResources, err := Marshal(resources)
	if err != nil {
		c.logger.Error(fmt.Sprintf("failed to marshal resources for versioning: %v", err))
		return ""
	}
	return c.hash(encodedResources)
}

func resourceGroup(version string, resources map[string]cache_types.Resource) cache.Resources {
	if len(resources) == 0 {
		return cache.Resources{Version: version}
	}
	items := make(map[string]cache_types.ResourceWithTTL, len(resources))
	for name, resource := range resources {
		items[name] = cache_types.ResourceWithTTL{Resource: resource}
	}
	return cache.Resources{
		Version: version,
		Items:   items,
	}
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

func resourceReferencesVersionContext(refs map[string]map[string]struct{}) string {
	parents := slices.Collect(maps.Keys(refs))
	slices.Sort(parents)

	var sb strings.Builder
	for _, parent := range parents {
		children := slices.Collect(maps.Keys(refs[parent]))
		slices.Sort(children)
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

type xdsSnapshotResourceView struct {
	resources *xds.Resources
}

func (view xdsSnapshotResourceView) listeners() iter.Seq2[string, *envoy_config_listener.Listener] {
	if view.resources == nil {
		return func(func(string, *envoy_config_listener.Listener) bool) {}
	}
	return maps.All(view.resources.Listeners)
}

func (view xdsSnapshotResourceView) clusters() iter.Seq2[string, *envoy_config_cluster.Cluster] {
	if view.resources == nil {
		return func(func(string, *envoy_config_cluster.Cluster) bool) {}
	}
	return maps.All(view.resources.Clusters)
}

type cacheSnapshotResourceView struct {
	resources cacheResources
}

func (view cacheSnapshotResourceView) listeners() iter.Seq2[string, *envoy_config_listener.Listener] {
	return func(yield func(string, *envoy_config_listener.Listener) bool) {
		for name, entry := range view.resources.listeners {
			if entry.resource != nil && !yield(name, entry.resource) {
				return
			}
		}
	}
}

func (view cacheSnapshotResourceView) clusters() iter.Seq2[string, *envoy_config_cluster.Cluster] {
	return func(yield func(string, *envoy_config_cluster.Cluster) bool) {
		for name, entry := range view.resources.clusters {
			if entry.resource != nil && !yield(name, entry.resource) {
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
	keys := slices.Collect(maps.Keys(resourceVersions))
	slices.Sort(keys)
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

func (c *cacheImpl) resourceVersions(typeURL typeurl.Index, resources map[string]cache_types.Resource, versionContext ...string) (string, map[string]string, error) {
	versions := make(map[string]string, len(resources))
	for name, resource := range resources {
		version, err := resourceContentVersion(resource)
		if err != nil {
			return "", nil, err
		}
		versions[name] = version
	}
	return c.resourceVersion(typeURL, versions, versionContext...), versions, nil
}

func (c *cacheImpl) updateResourceVersions(typeURL typeurl.Index, resources map[string]cache_types.Resource, previous cache.Resources, previousVersions map[string]string, versionContext ...string) (cache.Resources, map[string]string, error) {
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

	for name := range items {
		if _, exists := resources[name]; !exists {
			clone()
			delete(items, name)
			delete(versions, name)
		}
	}

	for name, resource := range resources {
		previousItem, resourceExists := items[name]
		_, versionExists := versions[name]
		if resourceExists && versionExists &&
			(previousItem.Resource == resource || proto.Equal(previousItem.Resource, resource)) {
			continue
		}

		version, err := resourceContentVersion(resource)
		if err != nil {
			return cache.Resources{}, nil, err
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

	version := c.resourceVersion(typeURL, versions, versionContext...)
	if !cloned && version == previous.Version {
		return previous, previousVersions, nil
	}
	return cache.Resources{
		Version: version,
		Items:   items,
	}, versions, nil
}

func snapshotResourceMap[V proto.Message](resources map[string]V) map[string]cache_types.Resource {
	result := make(map[string]cache_types.Resource, len(resources))
	for name, resource := range resources {
		result[name] = resource
	}
	return result
}

func snapshotResourcesForType(resources *xds.Resources, typeURL typeurl.Index) map[string]cache_types.Resource {
	if typeURL == typeurl.Endpoint {
		endpoints := make(map[string]cache_types.Resource, len(resources.Endpoints))
		for name, resource := range resources.Endpoints {
			// Skip wildcard :* endpoints that have no matching cluster,
			// as they cause snapshot inconsistency (EDS count > CDS references).
			// These are generated for backward compatibility with the old per-type
			// xDS caches but are not needed in the ADS snapshot.
			if _, hasCluster := resources.Clusters[name]; !hasCluster && strings.HasSuffix(name, ":*") {
				continue
			}
			endpoints[name] = resource
		}
		return endpoints
	}

	switch typeURL {
	case typeurl.Cluster:
		return snapshotResourceMap(resources.Clusters)
	case typeurl.Route:
		return snapshotResourceMap(resources.Routes)
	case typeurl.Listener:
		return snapshotResourceMap(resources.Listeners)
	case typeurl.Secret:
		return snapshotResourceMap(resources.Secrets)
	case typeurl.NetworkPolicy:
		return snapshotResourceMap(resources.NetworkPolicies)
	case typeurl.NetworkPolicyHosts:
		return snapshotResourceMap(resources.NetworkPolicyHosts)
	default:
		return nil
	}
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

// normalizeSnapshotResources returns the resource view used to build an ADS
// snapshot.
//
// Envoy expects every EDS-backed cluster in an ADS snapshot to have a matching
// ClusterLoadAssignment resource, even when the cluster currently has no
// endpoints. If CDS references an EDS resource that is absent from EDS, Envoy
// keeps the cluster warming and may not finish initialization, which also
// prevents it from requesting later resource types such as LDS/RDS/NPDS.
//
// The synthetic empty ClusterLoadAssignments are snapshot-local only. They must
// not be written back to the authoritative xds.Resources state, otherwise Cilium
// could retain generated placeholders after the corresponding clusters are
// removed and produce misleading diffs/reverts.
func normalizeSnapshotResources(resources *xds.Resources) *xds.Resources {
	var normalized *xds.Resources

	for _, cluster := range resources.Clusters {
		if cluster.GetType() != envoy_config_cluster.Cluster_EDS {
			continue
		}

		name := cluster.GetEdsClusterConfig().GetServiceName()
		if name == "" {
			name = cluster.GetName()
		}
		if name == "" {
			continue
		}

		if _, exists := resources.Endpoints[name]; exists {
			continue
		}

		if normalized == nil {
			copy := *resources
			copy.Endpoints = maps.Clone(resources.Endpoints)
			if copy.Endpoints == nil {
				copy.Endpoints = make(map[string]*envoy_config_endpoint.ClusterLoadAssignment)
			}
			normalized = &copy
		}
		normalized.Endpoints[name] = &envoy_config_endpoint.ClusterLoadAssignment{
			ClusterName: name,
		}
	}

	if normalized == nil {
		return resources
	}
	return normalized
}

func (c *cacheImpl) generateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	if resources == nil {
		empty := xds.NewResources()
		resources = &empty
	}

	resources = normalizeSnapshotResources(resources)
	view := xdsSnapshotResourceView{resources: resources}
	var resourceGroups typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Indices() {
		resourceMap := snapshotResourcesForType(resources, typeURL)
		version, versions, err := c.resourceVersions(typeURL, resourceMap, snapshotVersionContext(view, typeURL))
		if err != nil {
			return nil, err
		}
		resourceGroups[typeURL] = snapshotResourceGroup{
			resources: resourceGroup(version, resourceMap),
			versions:  versions,
		}
	}

	return newCiliumSnapshot(resourceGroups), nil
}

func (c *cacheImpl) generateSnapshotIncrementally(resources *xds.Resources, previous cache.ResourceSnapshot, changedTypeURLs typeurl.Set, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	previousSnapshot, regenerate, ok := c.canGenerateSnapshotIncrementally(previous, changedTypeURLs)
	if !ok {
		return c.generateSnapshot(resources, logger)
	}
	if regenerate.Empty() {
		return previousSnapshot, nil
	}

	if resources == nil {
		empty := xds.NewResources()
		resources = &empty
	}
	resources = normalizeSnapshotResources(resources)
	view := xdsSnapshotResourceView{resources: resources}

	resourceGroups := typeurl.Slots[snapshotResourceGroup](*previousSnapshot)
	for typeURL := range regenerate.Members() {
		resourceMap := snapshotResourcesForType(resources, typeURL)
		previousGroup := previousSnapshot[typeURL]
		group, versions, err := c.updateResourceVersions(
			typeURL,
			resourceMap,
			previousGroup.resources,
			previousGroup.versions,
			snapshotVersionContext(view, typeURL),
		)
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

// Once Cilium uses Go 1.27, consider making this a generic method on cacheImpl.
func resourceGroupFromEntries[V interface {
	proto.Message
	comparable
}](c *cacheImpl, typeURL typeurl.Index, resources map[string]resourceEntry[V], versionContext string) (cache.Resources, map[string]string, error) {
	items := make(map[string]cache_types.ResourceWithTTL, len(resources))
	versions := make(map[string]string, len(resources))
	var zero V
	for name, entry := range resources {
		if entry.resource == zero {
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

// Once Cilium uses Go 1.27, consider making this a generic method on cacheImpl.
func updateResourceEntries[V interface {
	proto.Message
	comparable
}](c *cacheImpl, typeURL typeurl.Index, resources map[string]resourceEntry[V], changed set.Set[string], previous cache.Resources, previousVersions map[string]string, versionContext string) (cache.Resources, map[string]string, error) {
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

	var zero V
	for name := range changed.Members() {
		resource := resources[name].resource
		previousItem, resourceExists := items[name]
		_, versionExists := versions[name]
		if resource == zero {
			if !resourceExists && !versionExists {
				continue
			}
			clone()
			delete(items, name)
			delete(versions, name)
			continue
		}
		if resourceExists && versionExists &&
			(previousItem.Resource == resource || proto.Equal(previousItem.Resource, resource)) {
			continue
		}

		version, err := resourceContentVersion(resource)
		if err != nil {
			return cache.Resources{}, nil, err
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

func desiredEndpoint(resources cacheResources, name string) (*envoy_config_endpoint.ClusterLoadAssignment, bool) {
	if endpoint, exists := currentResource(resources.endpoints, name); exists {
		if _, hasCluster := currentResource(resources.clusters, name); !hasCluster && strings.HasSuffix(name, ":*") {
			return nil, false
		}
		return endpoint, true
	}
	for clusterName, entry := range resources.clusters {
		if clusterEndpointName(clusterName, entry.resource) == name {
			return &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}, true
		}
	}
	return nil, false
}

func endpointResourceNames(resources cacheResources) map[string]struct{} {
	names := make(map[string]struct{}, len(resources.endpoints)+len(resources.clusters))
	for name := range resources.endpoints {
		names[name] = struct{}{}
	}
	for name, entry := range resources.clusters {
		if endpointName := clusterEndpointName(name, entry.resource); endpointName != "" {
			names[endpointName] = struct{}{}
		}
	}
	return names
}

func (state *nodeState) changedEndpointResourceNames(previous *ciliumSnapshot) set.Set[string] {
	if state.changed.clusters.Empty() {
		return state.changed.endpoints
	}
	names := state.changed.endpoints.Clone()
	previousClusters := previous[typeurl.Cluster].resources.Items
	for name := range state.changed.clusters.Members() {
		names.Insert(name)
		if item, exists := previousClusters[name]; exists {
			cluster, ok := item.Resource.(*envoy_config_cluster.Cluster)
			if ok {
				if oldName := clusterEndpointName(name, cluster); oldName != "" {
					names.Insert(oldName)
				}
			}
		}
		if entry := state.resources.clusters[name]; entry.resource != nil {
			if newName := clusterEndpointName(name, entry.resource); newName != "" {
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
		_, versionExists := versions[name]
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
			(previousItem.Resource == resource || proto.Equal(previousItem.Resource, resource)) {
			continue
		}
		version, err := resourceContentVersion(resource)
		if err != nil {
			return cache.Resources{}, nil, err
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
	view := cacheSnapshotResourceView{resources: state.resources}
	var resourceGroups typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Indices() {
		context := snapshotVersionContext(view, typeURL)
		var group cache.Resources
		var versions map[string]string
		var err error
		switch typeURL {
		case typeurl.Endpoint:
			group, versions, err = c.resourceGroupFromLookup(typeURL, endpointResourceNames(state.resources), func(name string) (cache_types.Resource, bool) {
				return desiredEndpoint(state.resources, name)
			}, context)
		case typeurl.Cluster:
			group, versions, err = resourceGroupFromEntries(c, typeURL, state.resources.clusters, context)
		case typeurl.Route:
			group, versions, err = resourceGroupFromEntries(c, typeURL, state.resources.routes, context)
		case typeurl.Listener:
			group, versions, err = resourceGroupFromEntries(c, typeURL, state.resources.listeners, context)
		case typeurl.Secret:
			group, versions, err = resourceGroupFromEntries(c, typeURL, state.resources.secrets, context)
		case typeurl.NetworkPolicy:
			group, versions, err = resourceGroupFromEntries(c, typeURL, state.resources.networkPolicies, context)
		case typeurl.NetworkPolicyHosts:
			group, versions, err = resourceGroupFromEntries(c, typeURL, state.resources.networkPolicyHosts, context)
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

	view := cacheSnapshotResourceView{resources: state.resources}
	resourceGroups := typeurl.Slots[snapshotResourceGroup](*previousSnapshot)
	for typeURL := range regenerate.Members() {
		context := snapshotVersionContext(view, typeURL)
		previousGroup := previousSnapshot[typeURL]
		var group cache.Resources
		var versions map[string]string
		var err error
		switch typeURL {
		case typeurl.Endpoint:
			group, versions, err = c.updateResourceLookup(typeURL, state.changedEndpointResourceNames(previousSnapshot), func(name string) (cache_types.Resource, bool) {
				return desiredEndpoint(state.resources, name)
			}, previousGroup.resources, previousGroup.versions, context)
		case typeurl.Cluster:
			group, versions, err = updateResourceEntries(c, typeURL, state.resources.clusters, state.changed.clusters, previousGroup.resources, previousGroup.versions, context)
		case typeurl.Route:
			group, versions, err = updateResourceEntries(c, typeURL, state.resources.routes, state.changed.routes, previousGroup.resources, previousGroup.versions, context)
		case typeurl.Listener:
			group, versions, err = updateResourceEntries(c, typeURL, state.resources.listeners, state.changed.listeners, previousGroup.resources, previousGroup.versions, context)
		case typeurl.Secret:
			group, versions, err = updateResourceEntries(c, typeURL, state.resources.secrets, state.changed.secrets, previousGroup.resources, previousGroup.versions, context)
		case typeurl.NetworkPolicy:
			group, versions, err = updateResourceEntries(c, typeURL, state.resources.networkPolicies, state.changed.networkPolicies, previousGroup.resources, previousGroup.versions, context)
		case typeurl.NetworkPolicyHosts:
			group, versions, err = updateResourceEntries(c, typeURL, state.resources.networkPolicyHosts, state.changed.networkPolicyHosts, previousGroup.resources, previousGroup.versions, context)
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

// setResources installs cache-private desired state for tests. It initializes
// the generation-aware maps while retaining the immutable protobuf pointers.
func (c *cacheImpl) setResources(nodeID string, resources *xds.Resources) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.nodeStates[nodeID] = &nodeState{
		resources: newCacheResources(resources, 0),
	}
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
	registeredCompletions   []*completion.Completion
	immediateCompletions    []immediateCompletion
	listenerChanges         []ListenerChange
	networkPolicyStateEmpty bool
	updateFailed            bool
	acceptedWG              *completion.WaitGroup
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

func (tx *resourceTransaction) addAccepted(wg *completion.WaitGroup, callbacks []func(error)) {
	for _, callback := range callbacks {
		tx.addAcceptedCallback(wg, callback)
	}
}

func (tx *resourceTransaction) addAcceptedCallback(wg *completion.WaitGroup, callback func(error)) {
	if wg == nil {
		return
	}
	if tx.acceptedWG == nil {
		tx.acceptedWG = wg
		tx.acceptedCallback = callback
		return
	}
	tx.acceptedCallbacks = append(tx.acceptedCallbacks, callback)
}

func (tx *resourceTransaction) complete() {
	c := tx.cache
	c.mutex.Unlock()
	c.deliverResponses(tx.deliveries)
	if tx.updateFailed {
		for _, comp := range tx.registeredCompletions {
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
	if tx.acceptedWG != nil {
		tx.acceptedWG.AddCompletionWithCallback(nil, tx.acceptedCallback).Complete(nil)
		for _, callback := range tx.acceptedCallbacks {
			tx.acceptedWG.AddCompletionWithCallback(nil, callback).Complete(nil)
		}
	}
}

func (c *cacheImpl) notifyListenerObserverUnlocked() {
	if c.listenerObserver.unlockedCallback != nil {
		c.listenerObserver.unlockedCallback()
	}
}

// notifyListenerObserverLocked publishes one transaction's listener
// transitions in cache commit order. The callback decides whether follow-up
// work is needed after the cache lock is released.
func (tx *resourceTransaction) notifyListenerObserverLocked() bool {
	observer := tx.cache.listenerObserver
	if tx.updateFailed || len(tx.listenerChanges) == 0 || observer.lockedCallback == nil ||
		observer.nodeID != tx.nodeID {
		return false
	}
	return observer.lockedCallback(tx.listenerChanges)
}

func (c *cacheImpl) registerGenerationCompletions(nodeID string, newSnapshot, oldSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, waits typeURLWaits, revertFunc RevertFunc) ([]*completion.Completion, []immediateCompletion) {
	completions := make([]*completion.Completion, 0, waits.Len())
	immediateCompletions := make([]immediateCompletion, 0, 1)
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
			completions = append(completions, comp)
		}
	}
	return completions, immediateCompletions
}

func (c *cacheImpl) registerStagedGenerationCompletions(nodeID string, networkPoliciesEmpty bool, wg *completion.WaitGroup, waits typeURLWaits, revertFunc RevertFunc) ([]*completion.Completion, []immediateCompletion) {
	completions := make([]*completion.Completion, 0, waits.Len())
	immediateCompletions := make([]immediateCompletion, 0, 1)
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
		completions = append(completions, comp)
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

func mergeStagedRollbacks(state *nodeState, base typeurl.Map[rollbackResources], typeURLs typeurl.Set, inverse cacheResources, generation uint64) typeurl.Map[rollbackResources] {
	if typeURLs.Empty() {
		return base
	}
	for typeURL := range typeURLs.Members() {
		rollback, _ := base.Get(typeURL)
		base.Set(typeURL, rollback.mergeTypeURL(state, typeURL, inverse, generation))
	}
	return base
}

// cloneRollbackResources copies the one typed map owned by a staged rollback
// slot. Other fields are empty because rollback state is partitioned by
// TypeURL before it is staged.
func cloneRollbackResources(typeURL typeurl.Index, rollback rollbackResources) rollbackResources {
	switch typeURL {
	case typeurl.Listener:
		rollback.listeners = maps.Clone(rollback.listeners)
	case typeurl.Route:
		rollback.routes = maps.Clone(rollback.routes)
	case typeurl.Cluster:
		rollback.clusters = maps.Clone(rollback.clusters)
	case typeurl.Endpoint:
		rollback.endpoints = maps.Clone(rollback.endpoints)
	case typeurl.Secret:
		rollback.secrets = maps.Clone(rollback.secrets)
	case typeurl.NetworkPolicy:
		rollback.networkPolicies = maps.Clone(rollback.networkPolicies)
	case typeurl.NetworkPolicyHosts:
		rollback.networkPolicyHosts = maps.Clone(rollback.networkPolicyHosts)
	}
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
	state.changed = changedResourceNames{}
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

func resourceEntries[V comparable](resources map[string]V, generation uint64) map[string]resourceEntry[V] {
	if len(resources) == 0 {
		return nil
	}
	entries := make(map[string]resourceEntry[V], len(resources))
	for name, resource := range resources {
		entries[name] = resourceEntry[V]{resource: resource, generation: generation}
	}
	return entries
}

func newCacheResources(resources *xds.Resources, generation uint64) cacheResources {
	if resources == nil {
		return cacheResources{}
	}
	return cacheResources{
		listeners:          resourceEntries(resources.Listeners, generation),
		routes:             resourceEntries(resources.Routes, generation),
		clusters:           resourceEntries(resources.Clusters, generation),
		endpoints:          resourceEntries(resources.Endpoints, generation),
		secrets:            resourceEntries(resources.Secrets, generation),
		networkPolicies:    resourceEntries(resources.NetworkPolicies, generation),
		networkPolicyHosts: resourceEntries(resources.NetworkPolicyHosts, generation),
	}
}

func currentResource[V comparable](resources map[string]resourceEntry[V], name string) (V, bool) {
	resource := resources[name].resource
	var zero V
	return resource, resource != zero
}

func prepareResourceMap[V interface {
	proto.Message
	comparable
}](current map[string]resourceEntry[V], removed, upserted map[string]V) (changedRemoved, changedUpserted map[string]V, inverse map[string]resourceEntry[V], changed bool) {
	// Single-resource transactions are the overwhelmingly common update path.
	// Reuse the caller's sparse map rather than allocating another one merely
	// to represent the same cache-private delta.
	if len(removed) == 0 && len(upserted) == 1 {
		for name, resource := range upserted {
			old := current[name]
			var zero V
			exists := old.resource != zero
			if exists && (old.resource == resource || proto.Equal(old.resource, resource)) {
				return nil, nil, nil, false
			}
			inverse = map[string]resourceEntry[V]{name: old}
			return nil, upserted, inverse, true
		}
	}
	if len(upserted) == 0 && len(removed) == 1 {
		for name := range removed {
			old := current[name]
			var zero V
			if old.resource == zero {
				return nil, nil, nil, false
			}
			inverse = map[string]resourceEntry[V]{name: old}
			return removed, nil, inverse, true
		}
	}

	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		old := current[name]
		var zero V
		if old.resource != zero {
			if changedRemoved == nil {
				changedRemoved = make(map[string]V)
			}
			changedRemoved[name] = zero
			if inverse == nil {
				inverse = make(map[string]resourceEntry[V])
			}
			inverse[name] = old
			changed = true
		}
	}
	for name, resource := range upserted {
		old := current[name]
		var zero V
		exists := old.resource != zero
		if exists && (old.resource == resource || proto.Equal(old.resource, resource)) {
			continue
		}
		if changedUpserted == nil {
			changedUpserted = make(map[string]V)
		}
		changedUpserted[name] = resource
		if inverse == nil {
			inverse = make(map[string]resourceEntry[V])
		}
		inverse[name] = old
		changed = true
	}
	return changedRemoved, changedUpserted, inverse, changed
}

func (state *nodeState) prepareResourceMutation(mutations ResourceMutations) (ResourceMutations, typeurl.Set, cacheResources) {
	var current cacheResources
	if state != nil {
		current = state.resources
	}
	removeSet := mutations.Removed
	upsertSet := mutations.Upserted
	var changes ResourceMutations
	var inverse cacheResources

	changedTypeURLs := typeurl.NewSet()
	var changed bool
	changes.Removed.Listeners, changes.Upserted.Listeners, inverse.listeners, changed = prepareResourceMap(current.listeners, removeSet.Listeners, upsertSet.Listeners)
	if changed {
		changedTypeURLs.Insert(typeurl.Listener)
	}
	changes.Removed.Routes, changes.Upserted.Routes, inverse.routes, changed = prepareResourceMap(current.routes, removeSet.Routes, upsertSet.Routes)
	if changed {
		changedTypeURLs.Insert(typeurl.Route)
	}
	changes.Removed.Clusters, changes.Upserted.Clusters, inverse.clusters, changed = prepareResourceMap(current.clusters, removeSet.Clusters, upsertSet.Clusters)
	if changed {
		changedTypeURLs.Insert(typeurl.Cluster)
	}
	changes.Removed.Endpoints, changes.Upserted.Endpoints, inverse.endpoints, changed = prepareResourceMap(current.endpoints, removeSet.Endpoints, upsertSet.Endpoints)
	if changed {
		changedTypeURLs.Insert(typeurl.Endpoint)
	}
	changes.Removed.Secrets, changes.Upserted.Secrets, inverse.secrets, changed = prepareResourceMap(current.secrets, removeSet.Secrets, upsertSet.Secrets)
	if changed {
		changedTypeURLs.Insert(typeurl.Secret)
	}
	changes.Removed.NetworkPolicies, changes.Upserted.NetworkPolicies, inverse.networkPolicies, changed = prepareResourceMap(current.networkPolicies, removeSet.NetworkPolicies, upsertSet.NetworkPolicies)
	if changed {
		changedTypeURLs.Insert(typeurl.NetworkPolicy)
	}
	changes.Removed.NetworkPolicyHosts, changes.Upserted.NetworkPolicyHosts, inverse.networkPolicyHosts, changed = prepareResourceMap(current.networkPolicyHosts, removeSet.NetworkPolicyHosts, upsertSet.NetworkPolicyHosts)
	if changed {
		changedTypeURLs.Insert(typeurl.NetworkPolicyHosts)
	}
	return changes, changedTypeURLs, inverse
}

func mergeRollbackMap[V comparable](state *nodeState, typeURL typeurl.Index, current map[string]rollbackEntry[V], desired map[string]resourceEntry[V], inverse map[string]resourceEntry[V], generation uint64) map[string]rollbackEntry[V] {
	if len(inverse) == 0 {
		return current
	}
	if current == nil {
		current = make(map[string]rollbackEntry[V], len(inverse))
	}
	for name, previous := range inverse {
		entry, exists := current[name]
		if !exists {
			entry.previous = previous
		}
		var zero V
		if desired[name].resource == zero {
			state.addRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: generation})
		}
		if exists {
			state.removeRollbackOwner(typeURL, rollbackOwnerKey{name: name, generation: entry.expectedGeneration})
		}
		entry.expectedGeneration = generation
		current[name] = entry
	}
	return current
}

func (rollback rollbackResources) mergeTypeURL(state *nodeState, typeURL typeurl.Index, inverse cacheResources, generation uint64) rollbackResources {
	switch typeURL {
	case typeurl.Listener:
		rollback.listeners = mergeRollbackMap(state, typeURL, rollback.listeners, state.resources.listeners, inverse.listeners, generation)
	case typeurl.Route:
		rollback.routes = mergeRollbackMap(state, typeURL, rollback.routes, state.resources.routes, inverse.routes, generation)
	case typeurl.Cluster:
		rollback.clusters = mergeRollbackMap(state, typeURL, rollback.clusters, state.resources.clusters, inverse.clusters, generation)
	case typeurl.Endpoint:
		rollback.endpoints = mergeRollbackMap(state, typeURL, rollback.endpoints, state.resources.endpoints, inverse.endpoints, generation)
	case typeurl.Secret:
		rollback.secrets = mergeRollbackMap(state, typeURL, rollback.secrets, state.resources.secrets, inverse.secrets, generation)
	case typeurl.NetworkPolicy:
		rollback.networkPolicies = mergeRollbackMap(state, typeURL, rollback.networkPolicies, state.resources.networkPolicies, inverse.networkPolicies, generation)
	case typeurl.NetworkPolicyHosts:
		rollback.networkPolicyHosts = mergeRollbackMap(state, typeURL, rollback.networkPolicyHosts, state.resources.networkPolicyHosts, inverse.networkPolicyHosts, generation)
	}
	return rollback
}

// mergeRollbackHistoryMap folds a newer, independently owned rollback into an
// older unsent one. The oldest previous value remains the rollback target,
// while the newest expected generation fences the combined rollback. Ownership
// of a superseded tombstone moves to the newer entry.
func mergeRollbackHistoryMap[V comparable](state *nodeState, typeURL typeurl.Index, older, newer map[string]rollbackEntry[V]) map[string]rollbackEntry[V] {
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
	rollback.listeners = mergeRollbackHistoryMap(state, typeurl.Listener, rollback.listeners, newer.listeners)
	rollback.routes = mergeRollbackHistoryMap(state, typeurl.Route, rollback.routes, newer.routes)
	rollback.clusters = mergeRollbackHistoryMap(state, typeurl.Cluster, rollback.clusters, newer.clusters)
	rollback.endpoints = mergeRollbackHistoryMap(state, typeurl.Endpoint, rollback.endpoints, newer.endpoints)
	rollback.secrets = mergeRollbackHistoryMap(state, typeurl.Secret, rollback.secrets, newer.secrets)
	rollback.networkPolicies = mergeRollbackHistoryMap(state, typeurl.NetworkPolicy, rollback.networkPolicies, newer.networkPolicies)
	rollback.networkPolicyHosts = mergeRollbackHistoryMap(state, typeurl.NetworkPolicyHosts, rollback.networkPolicyHosts, newer.networkPolicyHosts)
	return rollback
}

func filterResourceRevert[V comparable](current map[string]resourceEntry[V], rollback map[string]rollbackEntry[V]) (removed, upserted map[string]V, restored map[string]resourceEntry[V]) {
	var zero V
	for name, entry := range rollback {
		if current[name].generation != entry.expectedGeneration {
			continue
		}
		if restored == nil {
			restored = make(map[string]resourceEntry[V])
		}
		restored[name] = entry.previous
		if entry.previous.resource == zero {
			if removed == nil {
				removed = make(map[string]V)
			}
			removed[name] = zero
		} else {
			if upserted == nil {
				upserted = make(map[string]V)
			}
			upserted[name] = entry.previous.resource
		}
	}
	return removed, upserted, restored
}

func (state *nodeState) resourceRevert(rollback rollbackResources) (ResourceMutations, cacheResources) {
	if state == nil {
		return ResourceMutations{}, cacheResources{}
	}
	var revert ResourceMutations
	var restored cacheResources
	revert.Removed.Listeners, revert.Upserted.Listeners, restored.listeners = filterResourceRevert(state.resources.listeners, rollback.listeners)
	revert.Removed.Routes, revert.Upserted.Routes, restored.routes = filterResourceRevert(state.resources.routes, rollback.routes)
	revert.Removed.Clusters, revert.Upserted.Clusters, restored.clusters = filterResourceRevert(state.resources.clusters, rollback.clusters)
	revert.Removed.Endpoints, revert.Upserted.Endpoints, restored.endpoints = filterResourceRevert(state.resources.endpoints, rollback.endpoints)
	revert.Removed.Secrets, revert.Upserted.Secrets, restored.secrets = filterResourceRevert(state.resources.secrets, rollback.secrets)
	revert.Removed.NetworkPolicies, revert.Upserted.NetworkPolicies, restored.networkPolicies = filterResourceRevert(state.resources.networkPolicies, rollback.networkPolicies)
	revert.Removed.NetworkPolicyHosts, revert.Upserted.NetworkPolicyHosts, restored.networkPolicyHosts = filterResourceRevert(state.resources.networkPolicyHosts, rollback.networkPolicyHosts)
	return revert, restored
}

func filterInverseResourceRevert[V comparable](current, inverse map[string]resourceEntry[V], expectedGeneration uint64) (removed, upserted map[string]V, restored map[string]resourceEntry[V]) {
	var zero V
	for name, previous := range inverse {
		if current[name].generation != expectedGeneration {
			continue
		}
		if restored == nil {
			restored = make(map[string]resourceEntry[V])
		}
		restored[name] = previous
		if previous.resource == zero {
			if removed == nil {
				removed = make(map[string]V)
			}
			removed[name] = zero
		} else {
			if upserted == nil {
				upserted = make(map[string]V)
			}
			upserted[name] = previous.resource
		}
	}
	return removed, upserted, restored
}

func (state *nodeState) resourceRevertInverse(generation uint64, inverse cacheResources) (ResourceMutations, cacheResources) {
	if state == nil {
		return ResourceMutations{}, cacheResources{}
	}
	var mutations ResourceMutations
	var restored cacheResources
	mutations.Removed.Listeners, mutations.Upserted.Listeners, restored.listeners = filterInverseResourceRevert(state.resources.listeners, inverse.listeners, generation)
	mutations.Removed.Routes, mutations.Upserted.Routes, restored.routes = filterInverseResourceRevert(state.resources.routes, inverse.routes, generation)
	mutations.Removed.Clusters, mutations.Upserted.Clusters, restored.clusters = filterInverseResourceRevert(state.resources.clusters, inverse.clusters, generation)
	mutations.Removed.Endpoints, mutations.Upserted.Endpoints, restored.endpoints = filterInverseResourceRevert(state.resources.endpoints, inverse.endpoints, generation)
	mutations.Removed.Secrets, mutations.Upserted.Secrets, restored.secrets = filterInverseResourceRevert(state.resources.secrets, inverse.secrets, generation)
	mutations.Removed.NetworkPolicies, mutations.Upserted.NetworkPolicies, restored.networkPolicies = filterInverseResourceRevert(state.resources.networkPolicies, inverse.networkPolicies, generation)
	mutations.Removed.NetworkPolicyHosts, mutations.Upserted.NetworkPolicyHosts, restored.networkPolicyHosts = filterInverseResourceRevert(state.resources.networkPolicyHosts, inverse.networkPolicyHosts, generation)
	return mutations, restored
}

func updateRollbackOwnerMap[V comparable](state *nodeState, typeURL typeurl.Index, resources map[string]rollbackEntry[V], delta int) {
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
	updateRollbackOwnerMap(state, typeurl.Listener, rollback.listeners, delta)
	updateRollbackOwnerMap(state, typeurl.Route, rollback.routes, delta)
	updateRollbackOwnerMap(state, typeurl.Cluster, rollback.clusters, delta)
	updateRollbackOwnerMap(state, typeurl.Endpoint, rollback.endpoints, delta)
	updateRollbackOwnerMap(state, typeurl.Secret, rollback.secrets, delta)
	updateRollbackOwnerMap(state, typeurl.NetworkPolicy, rollback.networkPolicies, delta)
	updateRollbackOwnerMap(state, typeurl.NetworkPolicyHosts, rollback.networkPolicyHosts, delta)
}

func updateInverseRollbackOwnerMap[V comparable](state *nodeState, typeURL typeurl.Index, desired, inverse map[string]resourceEntry[V], generation uint64, delta int) {
	var zero V
	for name := range inverse {
		key := rollbackOwnerKey{name: name, generation: generation}
		if delta > 0 {
			if desired[name].resource == zero {
				state.addRollbackOwner(typeURL, key)
			}
		} else {
			state.removeRollbackOwner(typeURL, key)
		}
	}
}

func (state *nodeState) updateInverseRollbackOwners(inverse cacheResources, generation uint64, delta int) {
	updateInverseRollbackOwnerMap(state, typeurl.Listener, state.resources.listeners, inverse.listeners, generation, delta)
	updateInverseRollbackOwnerMap(state, typeurl.Route, state.resources.routes, inverse.routes, generation, delta)
	updateInverseRollbackOwnerMap(state, typeurl.Cluster, state.resources.clusters, inverse.clusters, generation, delta)
	updateInverseRollbackOwnerMap(state, typeurl.Endpoint, state.resources.endpoints, inverse.endpoints, generation, delta)
	updateInverseRollbackOwnerMap(state, typeurl.Secret, state.resources.secrets, inverse.secrets, generation, delta)
	updateInverseRollbackOwnerMap(state, typeurl.NetworkPolicy, state.resources.networkPolicies, inverse.networkPolicies, generation, delta)
	updateInverseRollbackOwnerMap(state, typeurl.NetworkPolicyHosts, state.resources.networkPolicyHosts, inverse.networkPolicyHosts, generation, delta)
}

func pruneReleasedTombstones[V comparable](state *nodeState, typeURL typeurl.Index, resources *map[string]resourceEntry[V], rollback map[string]rollbackEntry[V]) {
	var zero V
	for name, rollbackEntry := range rollback {
		entry := (*resources)[name]
		if entry.resource != zero || entry.generation != rollbackEntry.expectedGeneration {
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
	pruneReleasedTombstones(state, typeurl.Listener, &state.resources.listeners, rollback.listeners)
	pruneReleasedTombstones(state, typeurl.Route, &state.resources.routes, rollback.routes)
	pruneReleasedTombstones(state, typeurl.Cluster, &state.resources.clusters, rollback.clusters)
	pruneReleasedTombstones(state, typeurl.Endpoint, &state.resources.endpoints, rollback.endpoints)
	pruneReleasedTombstones(state, typeurl.Secret, &state.resources.secrets, rollback.secrets)
	pruneReleasedTombstones(state, typeurl.NetworkPolicy, &state.resources.networkPolicies, rollback.networkPolicies)
	pruneReleasedTombstones(state, typeurl.NetworkPolicyHosts, &state.resources.networkPolicyHosts, rollback.networkPolicyHosts)
}

func pruneInverseTombstones[V comparable](state *nodeState, typeURL typeurl.Index, resources *map[string]resourceEntry[V], inverse map[string]resourceEntry[V], generation uint64) {
	var zero V
	for name := range inverse {
		entry := (*resources)[name]
		if entry.resource != zero || entry.generation != generation {
			continue
		}
		key := rollbackOwnerKey{name: name, generation: generation}
		if state.rollbackOwnerCount(typeURL, key) == 0 {
			delete(*resources, name)
		}
	}
	if len(*resources) == 0 {
		*resources = nil
	}
}

func (state *nodeState) releaseInverseRollback(inverse cacheResources, generation uint64) {
	state.updateInverseRollbackOwners(inverse, generation, -1)
	pruneInverseTombstones(state, typeurl.Listener, &state.resources.listeners, inverse.listeners, generation)
	pruneInverseTombstones(state, typeurl.Route, &state.resources.routes, inverse.routes, generation)
	pruneInverseTombstones(state, typeurl.Cluster, &state.resources.clusters, inverse.clusters, generation)
	pruneInverseTombstones(state, typeurl.Endpoint, &state.resources.endpoints, inverse.endpoints, generation)
	pruneInverseTombstones(state, typeurl.Secret, &state.resources.secrets, inverse.secrets, generation)
	pruneInverseTombstones(state, typeurl.NetworkPolicy, &state.resources.networkPolicies, inverse.networkPolicies, generation)
	pruneInverseTombstones(state, typeurl.NetworkPolicyHosts, &state.resources.networkPolicyHosts, inverse.networkPolicyHosts, generation)
}

func markChangedNames[V any](changed *set.Set[string], removed, upserted map[string]V) {
	if len(removed) == 0 && len(upserted) == 0 {
		return
	}
	for name := range removed {
		changed.Insert(name)
	}
	for name := range upserted {
		changed.Insert(name)
	}
}

func commitResourceEntries[V comparable](current *map[string]resourceEntry[V], changed *set.Set[string], entries map[string]resourceEntry[V]) {
	if len(entries) == 0 {
		return
	}
	var zero resourceEntry[V]
	for name, entry := range entries {
		if entry == zero {
			delete(*current, name)
		} else {
			if *current == nil {
				*current = make(map[string]resourceEntry[V], len(entries))
			}
			(*current)[name] = entry
		}
		changed.Insert(name)
	}
}

func commitResourceMap[V comparable](current *map[string]resourceEntry[V], changed *set.Set[string], removed, upserted map[string]V, generation uint64, restored map[string]resourceEntry[V]) {
	if restored != nil {
		commitResourceEntries(current, changed, restored)
		return
	}
	if len(removed) == 0 && len(upserted) == 0 {
		return
	}
	if *current == nil {
		*current = make(map[string]resourceEntry[V], len(removed)+len(upserted))
	}
	for name := range removed {
		(*current)[name] = resourceEntry[V]{generation: generation}
	}
	for name, resource := range upserted {
		(*current)[name] = resourceEntry[V]{resource: resource, generation: generation}
	}
	markChangedNames(changed, removed, upserted)
}

func (state *nodeState) commitResourceMutation(changes ResourceMutations, generation uint64, restored *cacheResources) {
	var restore cacheResources
	if restored != nil {
		restore = *restored
	}
	commitResourceMap(&state.resources.listeners, &state.changed.listeners, changes.Removed.Listeners, changes.Upserted.Listeners, generation, restore.listeners)
	commitResourceMap(&state.resources.routes, &state.changed.routes, changes.Removed.Routes, changes.Upserted.Routes, generation, restore.routes)
	commitResourceMap(&state.resources.clusters, &state.changed.clusters, changes.Removed.Clusters, changes.Upserted.Clusters, generation, restore.clusters)
	commitResourceMap(&state.resources.endpoints, &state.changed.endpoints, changes.Removed.Endpoints, changes.Upserted.Endpoints, generation, restore.endpoints)
	commitResourceMap(&state.resources.secrets, &state.changed.secrets, changes.Removed.Secrets, changes.Upserted.Secrets, generation, restore.secrets)
	commitResourceMap(&state.resources.networkPolicies, &state.changed.networkPolicies, changes.Removed.NetworkPolicies, changes.Upserted.NetworkPolicies, generation, restore.networkPolicies)
	commitResourceMap(&state.resources.networkPolicyHosts, &state.changed.networkPolicyHosts, changes.Removed.NetworkPolicyHosts, changes.Upserted.NetworkPolicyHosts, generation, restore.networkPolicyHosts)
}

func committedListenerChanges(changes ResourceMutations, inverse cacheResources) []ListenerChange {
	if len(inverse.listeners) == 0 {
		return nil
	}
	listenerChanges := make([]ListenerChange, 0, len(inverse.listeners))
	for name, previous := range inverse.listeners {
		listenerChanges = append(listenerChanges, ListenerChange{
			Name:     name,
			Previous: previous.resource,
			Current:  changes.Upserted.Listeners[name],
		})
	}
	return listenerChanges
}

func (state *nodeState) restoreResourceEntries(inverse cacheResources) {
	commitResourceEntries(&state.resources.listeners, &state.changed.listeners, inverse.listeners)
	commitResourceEntries(&state.resources.routes, &state.changed.routes, inverse.routes)
	commitResourceEntries(&state.resources.clusters, &state.changed.clusters, inverse.clusters)
	commitResourceEntries(&state.resources.endpoints, &state.changed.endpoints, inverse.endpoints)
	commitResourceEntries(&state.resources.secrets, &state.changed.secrets, inverse.secrets)
	commitResourceEntries(&state.resources.networkPolicies, &state.changed.networkPolicies, inverse.networkPolicies)
	commitResourceEntries(&state.resources.networkPolicyHosts, &state.changed.networkPolicyHosts, inverse.networkPolicyHosts)
}

func reconcileChangedNames[V interface {
	proto.Message
	comparable
}](current map[string]resourceEntry[V], changed *set.Set[string], affected map[string]resourceEntry[V], published map[string]cache_types.ResourceWithTTL) {
	var zero V
	for name := range affected {
		resource := current[name].resource
		publishedResource, publishedExists := published[name]
		if resource == zero {
			if !publishedExists {
				changed.Remove(name)
			}
			continue
		}
		if publishedExists &&
			(publishedResource.Resource == resource || proto.Equal(publishedResource.Resource, resource)) {
			changed.Remove(name)
		}
	}
}

func (state *nodeState) reconcileChangedResourceNames(affected cacheResources, published cache.ResourceSnapshot) {
	resources := func(typeURL typeurl.Index) map[string]cache_types.ResourceWithTTL {
		if published == nil {
			return nil
		}
		return published.GetResourcesAndTTL(typeURL.URL())
	}
	reconcileChangedNames(state.resources.listeners, &state.changed.listeners, affected.listeners, resources(typeurl.Listener))
	reconcileChangedNames(state.resources.routes, &state.changed.routes, affected.routes, resources(typeurl.Route))
	reconcileChangedNames(state.resources.clusters, &state.changed.clusters, affected.clusters, resources(typeurl.Cluster))
	reconcileChangedNames(state.resources.endpoints, &state.changed.endpoints, affected.endpoints, resources(typeurl.Endpoint))
	reconcileChangedNames(state.resources.secrets, &state.changed.secrets, affected.secrets, resources(typeurl.Secret))
	reconcileChangedNames(state.resources.networkPolicies, &state.changed.networkPolicies, affected.networkPolicies, resources(typeurl.NetworkPolicy))
	reconcileChangedNames(state.resources.networkPolicyHosts, &state.changed.networkPolicyHosts, affected.networkPolicyHosts, resources(typeurl.NetworkPolicyHosts))
}

func cacheResourcesEmpty(resources cacheResources) bool {
	return len(resources.listeners) == 0 && len(resources.routes) == 0 &&
		len(resources.clusters) == 0 && len(resources.endpoints) == 0 &&
		len(resources.secrets) == 0 && len(resources.networkPolicies) == 0 &&
		len(resources.networkPolicyHosts) == 0
}

func resourceMutationsEmpty(mutations ResourceMutations) bool {
	return len(mutations.Removed.Listeners) == 0 && len(mutations.Upserted.Listeners) == 0 &&
		len(mutations.Removed.Routes) == 0 && len(mutations.Upserted.Routes) == 0 &&
		len(mutations.Removed.Clusters) == 0 && len(mutations.Upserted.Clusters) == 0 &&
		len(mutations.Removed.Endpoints) == 0 && len(mutations.Upserted.Endpoints) == 0 &&
		len(mutations.Removed.Secrets) == 0 && len(mutations.Upserted.Secrets) == 0 &&
		len(mutations.Removed.NetworkPolicies) == 0 && len(mutations.Upserted.NetworkPolicies) == 0 &&
		len(mutations.Removed.NetworkPolicyHosts) == 0 && len(mutations.Upserted.NetworkPolicyHosts) == 0
}

func resourceEntriesEmpty[V comparable](resources map[string]resourceEntry[V]) bool {
	var zero V
	for _, entry := range resources {
		if entry.resource != zero {
			return false
		}
	}
	return true
}

func (state *nodeState) networkPoliciesEmpty() bool {
	if state == nil {
		return true
	}
	return resourceEntriesEmpty(state.resources.networkPolicies)
}

// ApplyResources applies sparse removals and upserts to the cache-private
// desired state. It is the authority for semantic no-op detection, changed
// resource names and generation-fenced reverts. Published maps remain immutable
// and are updated copy-on-write only when the staged snapshot is finalized.
func (c *cacheImpl) ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyResourcesLocked(mutations, wg, updatedTypeURLs, nil)
	notifyObserver := tx.notifyListenerObserverLocked()
	tx.complete()
	if notifyObserver {
		c.notifyListenerObserverUnlocked()
	}
	return updated, revertFunc, finalizeFunc, err
}

func prepareSingleResource[V interface {
	proto.Message
	comparable
}](current map[string]resourceEntry[V], name string, resource V) (previous resourceEntry[V], desired V, desiredExists, changed bool) {
	previous = current[name]
	var zero V
	if resource == zero {
		return previous, zero, false, previous.resource != zero
	}
	if previous.resource != zero && (previous.resource == resource || proto.Equal(previous.resource, resource)) {
		return previous, previous.resource, true, false
	}
	return previous, resource, true, true
}

// finishUnchangedSingleResourceLocked attaches a no-op update directly to the
// resource's current ACK state without constructing a broad ResourceMutations
// value or inspecting unrelated resource types. Caller must hold mutex.
func (tx *resourceTransaction) finishUnchangedSingleResourceLocked(typeURL typeurl.Index, name string, generation uint64, desired proto.Message, desiredExists bool, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	if wg == nil {
		return false, nil, nil, nil
	}
	if tx.cache.completionCbs.ResourceAccepted(tx.nodeID, typeURL, name, desired, desiredExists) {
		tx.addAcceptedCallback(wg, callback)
		return false, nil, nil, nil
	}
	var waits typeURLWaits
	waits.Set(typeURL, generationWait{callback: callback, generation: generation})
	return false, nil, nil, tx.awaitCurrentVersionLocked(wg, waits)
}

// applyChangedSingleResourceLocked sends an already-prepared typed mutation
// through the shared generation, revert, and lazy-publication machinery. It
// handles completion state directly because the affected resource and TypeURL
// are already known. Caller must hold mutex.
func (tx *resourceTransaction) applyChangedSingleResourceLocked(typeURL typeurl.Index, name string, desired proto.Message, desiredExists bool, changes ResourceMutations, inverse cacheResources, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	c := tx.cache
	c.resourceGeneration++
	tx.generation = c.resourceGeneration
	changedTypeURLs := typeurl.NewSet(typeURL)
	lifecycle := c.newCallerRollbackLifecycle(tx.ctx, tx.nodeID, tx.generation, inverse)
	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)

	accepted := false
	var changedWaits typeURLWaits
	if wg != nil {
		accepted = c.completionCbs.ResourceAccepted(tx.nodeID, typeURL, name, desired, desiredExists)
		if !accepted {
			changedWaits.Set(typeURL, generationWait{callback: callback, generation: tx.generation})
		}
	}
	err := tx.updateResourceChangesLocked(changes, inverse, dirtyTypeURLs, changedTypeURLs, c.defaultGenerator, wg, changedWaits, lifecycle, nil)
	if err != nil {
		return false, nil, nil, err
	}
	if accepted {
		tx.addAcceptedCallback(wg, callback)
	}
	revertFunc, finalizeFunc := lifecycle.functions()
	return true, revertFunc, finalizeFunc, nil
}

func (tx *resourceTransaction) applyListenerLocked(name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	state := tx.state
	stateExists := state != nil
	var current map[string]resourceEntry[*envoy_config_listener.Listener]
	if state != nil {
		current = state.resources.listeners
	}
	previous, desired, desiredExists, changed := prepareSingleResource(current, name, resource)
	if !changed {
		if stateExists {
			return tx.finishUnchangedSingleResourceLocked(typeurl.Listener, name, previous.generation, desired, desiredExists, wg, callback)
		}
		tx.addAcceptedCallback(wg, callback)
		return false, nil, nil, nil
	}

	var mutations ResourceMutations
	if resource == nil {
		mutations.Removed.Listeners = map[string]*envoy_config_listener.Listener{name: nil}
	} else {
		mutations.Upserted.Listeners = map[string]*envoy_config_listener.Listener{name: resource}
	}
	tx.listenerChanges = []ListenerChange{{Name: name, Previous: previous.resource, Current: resource}}
	inverse := cacheResources{listeners: map[string]resourceEntry[*envoy_config_listener.Listener]{name: previous}}
	return tx.applyChangedSingleResourceLocked(typeurl.Listener, name, desired, desiredExists, mutations, inverse, wg, callback)
}

func (tx *resourceTransaction) applyNetworkPolicyLocked(name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	state := tx.state
	stateExists := state != nil
	var current map[string]resourceEntry[*cilium.NetworkPolicy]
	if state != nil {
		current = state.resources.networkPolicies
	}
	previous, desired, desiredExists, changed := prepareSingleResource(current, name, resource)
	if !changed {
		if stateExists {
			return tx.finishUnchangedSingleResourceLocked(typeurl.NetworkPolicy, name, previous.generation, desired, desiredExists, wg, callback)
		}
		tx.addAcceptedCallback(wg, callback)
		return false, nil, nil, nil
	}

	var mutations ResourceMutations
	if resource == nil {
		mutations.Removed.NetworkPolicies = map[string]*cilium.NetworkPolicy{name: nil}
	} else {
		mutations.Upserted.NetworkPolicies = map[string]*cilium.NetworkPolicy{name: resource}
	}
	inverse := cacheResources{networkPolicies: map[string]resourceEntry[*cilium.NetworkPolicy]{name: previous}}
	return tx.applyChangedSingleResourceLocked(typeurl.NetworkPolicy, name, desired, desiredExists, mutations, inverse, wg, callback)
}

func (tx *resourceTransaction) applyNetworkPolicyHostsLocked(name string, resource *cilium.NetworkPolicyHosts) (bool, RevertFunc, FinalizeFunc, error) {
	state := tx.state
	var current map[string]resourceEntry[*cilium.NetworkPolicyHosts]
	if state != nil {
		current = state.resources.networkPolicyHosts
	}
	previous, desired, desiredExists, changed := prepareSingleResource(current, name, resource)
	if !changed {
		return false, nil, nil, nil
	}

	var mutations ResourceMutations
	if resource == nil {
		mutations.Removed.NetworkPolicyHosts = map[string]*cilium.NetworkPolicyHosts{name: nil}
	} else {
		mutations.Upserted.NetworkPolicyHosts = map[string]*cilium.NetworkPolicyHosts{name: resource}
	}
	inverse := cacheResources{networkPolicyHosts: map[string]resourceEntry[*cilium.NetworkPolicyHosts]{name: previous}}
	return tx.applyChangedSingleResourceLocked(typeurl.NetworkPolicyHosts, name, desired, desiredExists, mutations, inverse, nil, nil)
}

func (c *cacheImpl) UpsertListener(ctx context.Context, nodeID, name string, resource *envoy_config_listener.Listener, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyListenerLocked(name, resource, wg, callback)
	notifyObserver := tx.notifyListenerObserverLocked()
	tx.complete()
	if notifyObserver {
		c.notifyListenerObserverUnlocked()
	}
	return updated, revertFunc, finalizeFunc, err
}

func (c *cacheImpl) RemoveListener(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyListenerLocked(name, nil, wg, callback)
	notifyObserver := tx.notifyListenerObserverLocked()
	tx.complete()
	if notifyObserver {
		c.notifyListenerObserverUnlocked()
	}
	return updated, revertFunc, finalizeFunc, err
}

func (c *cacheImpl) UpsertNetworkPolicy(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicy, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyNetworkPolicyLocked(name, resource, wg, callback)
	tx.complete()
	return updated, revertFunc, finalizeFunc, err
}

func (c *cacheImpl) RemoveNetworkPolicy(ctx context.Context, nodeID, name string, wg *completion.WaitGroup, callback func(error)) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyNetworkPolicyLocked(name, nil, wg, callback)
	tx.complete()
	return updated, revertFunc, finalizeFunc, err
}

func (c *cacheImpl) UpsertNetworkPolicyHosts(ctx context.Context, nodeID, name string, resource *cilium.NetworkPolicyHosts) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyNetworkPolicyHostsLocked(name, resource)
	tx.complete()
	return updated, revertFunc, finalizeFunc, err
}

func (c *cacheImpl) RemoveNetworkPolicyHosts(ctx context.Context, nodeID, name string) (bool, RevertFunc, FinalizeFunc, error) {
	tx := c.beginResourceTransaction(ctx, nodeID)
	updated, revertFunc, finalizeFunc, err := tx.applyNetworkPolicyHostsLocked(name, nil)
	tx.complete()
	return updated, revertFunc, finalizeFunc, err
}

// applyResourcesLocked allocates generations and constructs generation-fenced
// reverts inside the cache. Caller must hold mutex.
func (tx *resourceTransaction) applyResourcesLocked(mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks, restoredEntries *cacheResources) (bool, RevertFunc, FinalizeFunc, error) {
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
		return false, nil, nil, nil
	}
	resourcesChanged := !changedTypeURLs.Empty()
	if !resourcesChanged {
		updated, err := tx.applyPreparedResourcesLocked(ResourceMutations{}, cacheResources{}, typeurl.NewSet(), typeurl.NewSet(), false, mutations, wg, updatedTypeURLs, nil, restoredEntries)
		return updated, nil, nil, err
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
		return false, nil, nil, err
	}
	if len(inverse.listeners) > 0 {
		tx.listenerChanges = committedListenerChanges(changes, inverse)
	}
	if lifecycle == nil {
		return updated, nil, nil, nil
	}
	revertFunc, finalizeFunc := lifecycle.functions()
	return updated, revertFunc, finalizeFunc, nil
}

func mutationTypeURLs(mutations ResourceMutations) typeurl.Set {
	typeURLs := typeurl.NewSet()
	add := func(typeURL typeurl.Index, changed bool) {
		if !changed {
			return
		}
		typeURLs.Insert(typeURL)
	}
	add(typeurl.Listener, len(mutations.Removed.Listeners) > 0 || len(mutations.Upserted.Listeners) > 0)
	add(typeurl.Route, len(mutations.Removed.Routes) > 0 || len(mutations.Upserted.Routes) > 0)
	add(typeurl.Cluster, len(mutations.Removed.Clusters) > 0 || len(mutations.Upserted.Clusters) > 0)
	add(typeurl.Endpoint, len(mutations.Removed.Endpoints) > 0 || len(mutations.Upserted.Endpoints) > 0)
	add(typeurl.Secret, len(mutations.Removed.Secrets) > 0 || len(mutations.Upserted.Secrets) > 0)
	add(typeurl.NetworkPolicy, len(mutations.Removed.NetworkPolicies) > 0 || len(mutations.Upserted.NetworkPolicies) > 0)
	add(typeurl.NetworkPolicyHosts, len(mutations.Removed.NetworkPolicyHosts) > 0 || len(mutations.Upserted.NetworkPolicyHosts) > 0)
	return typeURLs
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

// newRollbackLifecycle owns one rollback view until exactly one terminal
// operation is selected. Duplicate terminal calls are programming errors, but
// are deliberately harmless because revert/finalize functions cross several
// asynchronous ownership boundaries.
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

func (c *cacheImpl) newCallerRollbackLifecycle(ctx context.Context, nodeID string, generation uint64, inverse cacheResources) *rollbackLifecycle {
	return &rollbackLifecycle{
		cache:      c,
		ctx:        ctx,
		nodeID:     nodeID,
		typeURL:    typeurl.Count,
		generation: generation,
		inverse:    inverse,
	}
}

func (lifecycle *rollbackLifecycle) warnDuplicateLocked(operation string) {
	lifecycle.cache.logger.Warn("Ignoring duplicate resource update terminal operation",
		logfields.NodeID, lifecycle.nodeID,
		logfields.XDSGeneration, lifecycle.generation,
		logfields.Operation, operation)
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

// completedLocked reports whether a terminal operation has consumed the
// lifecycle's rollback payload. Caller must hold cacheImpl.mutex.
func (lifecycle *rollbackLifecycle) completedLocked() bool {
	return lifecycle.resources == nil && cacheResourcesEmpty(lifecycle.inverse)
}

// takeRollbackLocked atomically selects the lifecycle's terminal operation and
// returns its rollback payload. Clearing both payload representations marks the
// lifecycle complete while retaining identifying fields for duplicate warnings.
// Caller must hold cacheImpl.mutex.
func (lifecycle *rollbackLifecycle) takeRollbackLocked(operation string) (*rollbackResources, cacheResources, bool) {
	if lifecycle.completedLocked() {
		lifecycle.warnDuplicateLocked(operation)
		return nil, cacheResources{}, false
	}
	resources, inverse := lifecycle.resources, lifecycle.inverse
	lifecycle.resources = nil
	lifecycle.inverse = cacheResources{}
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

func (lifecycle *rollbackLifecycle) Finalize() {
	c := lifecycle.cache
	c.mutex.Lock()
	lifecycle.finalizeLocked()
	c.mutex.Unlock()
}

func (lifecycle *rollbackLifecycle) Revert(expectedGeneration uint64) (uint64, bool) {
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
	var mutations ResourceMutations
	var restoredEntries cacheResources
	if resources == nil {
		mutations, restoredEntries = state.resourceRevertInverse(lifecycle.generation, inverse)
	} else {
		mutations, restoredEntries = state.resourceRevert(*resources)
	}
	if state != nil {
		if resources == nil {
			state.releaseInverseRollback(inverse, lifecycle.generation)
		} else {
			state.releaseRollback(*resources)
		}
	}
	if resourceMutationsEmpty(mutations) {
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
	updated, _, _, err := tx.applyResourcesLocked(mutations, nil, TypeURLCallbacks{}, &restoredEntries)
	currentGeneration = tx.currentResourceGeneration()
	notifyObserver := tx.notifyListenerObserverLocked()
	tx.complete()
	if notifyObserver {
		c.notifyListenerObserverUnlocked()
	}
	if err != nil {
		c.logger.Error("Failed to revert snapshot",
			logfields.NodeID, lifecycle.nodeID,
			logfields.Error, err)
		return currentGeneration, false
	}
	return currentGeneration, updated
}

func (lifecycle *rollbackLifecycle) functions() (RevertFunc, FinalizeFunc) {
	return lifecycle.Revert, lifecycle.Finalize
}

func resourceMutationAccepted[V interface {
	proto.Message
	comparable
}](completionCbs *callbacks.CompletionCallbacks, nodeID string, typeURL typeurl.Index, current map[string]resourceEntry[V], removed, upserted map[string]V, typeChanged bool) bool {
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
		// already-ACKed no-op does not pay for the same proto.Equal twice.
		if !typeChanged {
			if cached, exists := currentResource(current, name); exists {
				resource = cached
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
func resourceMutationGeneration[V comparable](current map[string]resourceEntry[V], removed, upserted map[string]V) (uint64, bool) {
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
	var current cacheResources
	if state != nil {
		current = state.resources
	}
	var found bool
	var generation uint64
	switch typeURL {
	case typeurl.Listener:
		generation, found = resourceMutationGeneration(current.listeners, mutations.Removed.Listeners, mutations.Upserted.Listeners)
	case typeurl.Route:
		generation, found = resourceMutationGeneration(current.routes, mutations.Removed.Routes, mutations.Upserted.Routes)
	case typeurl.Cluster:
		generation, found = resourceMutationGeneration(current.clusters, mutations.Removed.Clusters, mutations.Upserted.Clusters)
	case typeurl.Endpoint:
		generation, found = resourceMutationGeneration(current.endpoints, mutations.Removed.Endpoints, mutations.Upserted.Endpoints)
	case typeurl.Secret:
		generation, found = resourceMutationGeneration(current.secrets, mutations.Removed.Secrets, mutations.Upserted.Secrets)
	case typeurl.NetworkPolicy:
		generation, found = resourceMutationGeneration(current.networkPolicies, mutations.Removed.NetworkPolicies, mutations.Upserted.NetworkPolicies)
	case typeurl.NetworkPolicyHosts:
		generation, found = resourceMutationGeneration(current.networkPolicyHosts, mutations.Removed.NetworkPolicyHosts, mutations.Upserted.NetworkPolicyHosts)
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
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.listeners, mutations.Removed.Listeners, mutations.Upserted.Listeners, typeChanged)
	case typeurl.Route:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.routes, mutations.Removed.Routes, mutations.Upserted.Routes, typeChanged)
	case typeurl.Cluster:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.clusters, mutations.Removed.Clusters, mutations.Upserted.Clusters, typeChanged)
	case typeurl.Endpoint:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.endpoints, mutations.Removed.Endpoints, mutations.Upserted.Endpoints, typeChanged)
	case typeurl.Secret:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.secrets, mutations.Removed.Secrets, mutations.Upserted.Secrets, typeChanged)
	case typeurl.NetworkPolicy:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.networkPolicies, mutations.Removed.NetworkPolicies, mutations.Upserted.NetworkPolicies, typeChanged)
	case typeurl.NetworkPolicyHosts:
		return resourceMutationAccepted(c.completionCbs, tx.nodeID, typeURL, state.resources.networkPolicyHosts, mutations.Removed.NetworkPolicyHosts, mutations.Upserted.NetworkPolicyHosts, typeChanged)
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
func (tx *resourceTransaction) applyPreparedResourcesLocked(changes ResourceMutations, inverse cacheResources, changedTypeURLs, watchTypeURLs typeurl.Set, resourcesChanged bool, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks, lifecycle *rollbackLifecycle, restoredEntries *cacheResources) (bool, error) {
	var dirtyTypeURLs typeurl.Set
	if resourcesChanged {
		dirtyTypeURLs = snapshotTypesChangedBy(changedTypeURLs)
	}
	var changedWaits, unchangedWaits typeURLWaits
	var acceptedCompletions []func(error)
	for typeURL, callback := range updatedTypeURLs.All() {
		typeChanged := changedTypeURLs.Has(typeURL)
		if tx.resourcesAcceptedLocked(typeURL, mutations, typeChanged) {
			acceptedCompletions = append(acceptedCompletions, callback)
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
		tx.addAccepted(wg, acceptedCompletions)
		return false, err
	}
	err := tx.updateResourceChangesLocked(changes, inverse, dirtyTypeURLs, watchTypeURLs, tx.cache.defaultGenerator, wg, changedWaits, lifecycle, restoredEntries)
	if err != nil {
		return false, err
	}
	err = tx.awaitCurrentVersionLocked(wg, unchangedWaits)
	tx.addAccepted(wg, acceptedCompletions)
	if err != nil {
		return true, err
	}
	return true, nil
}

// updateResourceChangesLocked commits one prepared mutation and optionally
// finalizes it for an open watch. Caller must hold mutex; post-lock work is
// accumulated on tx.
func (tx *resourceTransaction) updateResourceChangesLocked(changes ResourceMutations, inverse cacheResources, dirtyTypeURLs, watchTypeURLs typeurl.Set, generator snapshotGenerator, wg *completion.WaitGroup, waits typeURLWaits, lifecycle *rollbackLifecycle, restoredEntries *cacheResources) error {
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
	if !stateExisted {
		// The first desired state must establish a complete baseline for whichever
		// supported resource type Envoy requests first.
		watchTypeURLs = snapshotTypesChangedBy(typeurl.Set{})
	}
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
		rollbacks = mergeStagedRollbacks(state, rollbacks, rollbackTypeURLs, inverse, tx.generation)
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
		if stateExisted {
			state.restoreResourceEntries(inverse)
			// Re-establish the old stage ownership before releasing the failed
			// replacement so shared tombstones remain continuously guarded.
			if oldStaged != nil {
				state.acquireRollbackSet(oldStagedValue.rollbacks)
			}
			state.releaseRollbackSet(rollbacks)
			published, _ := c.SnapshotCache.GetSnapshot(tx.nodeID)
			state.reconcileChangedResourceNames(inverse, published)
			state.resourceGeneration = oldResourceGeneration
			if oldStaged == nil {
				state.staged = nil
			} else {
				*oldStaged = oldStagedValue
				state.staged = oldStaged
			}
		} else {
			delete(c.nodeStates, tx.nodeID)
			tx.state = nil
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
	if state == nil {
		return nil, false
	}
	switch typeURL {
	case typeurl.Listener:
		return currentResource(state.resources.listeners, resourceName)
	case typeurl.Route:
		return currentResource(state.resources.routes, resourceName)
	case typeurl.Cluster:
		return currentResource(state.resources.clusters, resourceName)
	case typeurl.Endpoint:
		return currentResource(state.resources.endpoints, resourceName)
	case typeurl.Secret:
		return currentResource(state.resources.secrets, resourceName)
	case typeurl.NetworkPolicy:
		return currentResource(state.resources.networkPolicies, resourceName)
	case typeurl.NetworkPolicyHosts:
		return currentResource(state.resources.networkPolicyHosts, resourceName)
	default:
		return nil, false
	}
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
		for name, entry := range state.resources.listeners {
			if entry.resource != nil && !yield(name, entry.resource) {
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
		for name, entry := range state.resources.routes {
			if entry.resource != nil && !yield(name, entry.resource) {
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
		for name, entry := range state.resources.networkPolicies {
			if entry.resource != nil && !yield(name, entry.resource) {
				return
			}
		}
	}
}

func (c *cacheImpl) SetListenerObserver(nodeID string, lockedCallback func(changes []ListenerChange) bool, unlockedCallback func()) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.listenerObserver.lockedCallback != nil {
		c.logger.Warn("Replacing xDS cache listener observer", logfields.NodeID, nodeID)
	}
	c.listenerObserver = listenerObserver{
		nodeID:           nodeID,
		lockedCallback:   lockedCallback,
		unlockedCallback: unlockedCallback,
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
