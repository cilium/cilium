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

	// ApplyResources commits semantic changes and retains cache-owned NACK
	// rollback. Completions for unchanged resource types attach to their current
	// version instead of creating a completion-only generation.
	ApplyResources(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) error
	// ApplyResourcesWithRollback also returns a caller-owned rollback lifecycle
	// for a changed update. The caller must eventually Finalize or Revert it;
	// either call is terminal even if Revert returns an error.
	ApplyResourcesWithRollback(ctx context.Context, nodeID string, mutations ResourceMutations, wg *completion.WaitGroup, updatedTypeURLs TypeURLCallbacks) (Rollback, error)
	// ApplyResource compares only the named resource and builds a sparse mutation
	// only after detecting an actual semantic change. It accepts every supported
	// typeURL. A nil resource removes the named resource; typeURL identifies its
	// type even for removals.
	ApplyResource(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error)) error
	// ApplyResourceWithRollback also returns a caller-owned rollback lifecycle
	// for a changed update. The caller must eventually Finalize or Revert it;
	// either call is terminal even if Revert returns an error.
	ApplyResourceWithRollback(ctx context.Context, nodeID string, typeURL typeurl.Index, name string, resource proto.Message, wg *completion.WaitGroup, callback func(error)) (Rollback, error)
	// GetResource returns one cache-owned immutable resource without
	// materializing the complete desired resource maps, or nil if absent.
	GetResource(nodeID string, typeURL typeurl.Index, resourceName string) cache_types.Resource
	// Resource iterators expose cache-owned immutable resources without
	// leaking the mutable internal maps. Iteration holds the cache read lock,
	// so loop bodies must not call back into the cache.
	Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener]
	Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration]
	NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy]
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
	// HasNode reports whether this consumer was configured at cache construction.
	// An empty desired state remains authoritative across stream reconnects.
	HasNode(nodeID string) bool
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
	cache.SnapshotCache

	// mutex protects cache state and serializes complete resource mutations.
	// Mutations hold the write lock from semantic comparison through publication,
	// then release it before delivering responses or completions.
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
	strictAdsMode bool
	completionCbs *callbacks.CompletionCallbacks
	// resourceGeneration is the latest number reserved from the shared mutation
	// sequence. Only nextResourceGenerationLocked advances it, under mutex.
	resourceGeneration callbacks.Generation
	// listenerObserver is supplied by the ADS server. A nil observer leaves
	// standalone cache users' explicit ACK waits unchanged.
	listenerObserver ListenerObserver
}

// snapshotPublication describes completion finalization and response rollback
// ownership when installing a snapshot for generation.
type snapshotPublication struct {
	generation callbacks.Generation
	// Every present resource type needs completion finalization, including
	// unchanged dependent types whose snapshot version changes. A nonempty
	// value also supplies response-owned rollback state; an empty value means
	// finalize only (including publications made by a revert). Absent types
	// require neither.
	resourceTypes typeurl.Map[rollbackResources]
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
		watchRelays:   make(map[chan cache.Response]*watchRelay),
		logger:        logger,
		strictAdsMode: strictAdsMode,
	}
	c.completionCbs = callbacks.NewCompletionCallbacks(logger, c)
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

// snapshotResourceView is a temporary bridge preserving the existing
// parent-reference content-version helpers as resources move into cache-private
// state. It and those helpers are removed later in this series by
// "envoy: derive ADS versions from generations".
type snapshotResourceView interface {
	listeners() iter.Seq2[string, *envoy_config_listener.Listener]
	clusters() iter.Seq2[string, *envoy_config_cluster.Cluster]
}

// cacheSnapshotResourceView adapts cache-private entries to the typed view
// expected by the existing version-context helpers, without copying resource
// maps and excluding removal tombstones. This temporary adapter is removed with
// snapshotResourceView in "envoy: derive ADS versions from generations".
type cacheSnapshotResourceView struct {
	resources *resourceMaps
}

func (view cacheSnapshotResourceView) listeners() iter.Seq2[string, *envoy_config_listener.Listener] {
	return func(yield func(string, *envoy_config_listener.Listener) bool) {
		for name, entry := range view.resources[typeurl.Listener] {
			if entry.resource != nil && !yield(name, typedResource[*envoy_config_listener.Listener](entry.resource)) {
				return
			}
		}
	}
}

func (view cacheSnapshotResourceView) clusters() iter.Seq2[string, *envoy_config_cluster.Cluster] {
	return func(yield func(string, *envoy_config_cluster.Cluster) bool) {
		for name, entry := range view.resources[typeurl.Cluster] {
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

// snapshotVersionContext preserves dependency-sensitive content versioning:
// changed parent references alter a dependent type's version even when its
// resources are unchanged. It is part of the temporary snapshotResourceView
// bridge, removed later in this series by
// "envoy: derive ADS versions from generations", which uses generation-based
// versions and targeted EDS replay instead.
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

func (c *cacheImpl) generateSnapshotFromState(state *nodeState) (cache.ResourceSnapshot, error) {
	view := cacheSnapshotResourceView{resources: &state.resources}
	var resourceGroups typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Indices() {
		versionContext := snapshotVersionContext(view, typeURL)
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
				if entry.resource == nil {
					continue
				}
				if name := clusterEndpointName(clusterName, typedResource[*envoy_config_cluster.Cluster](entry.resource)); name != "" {
					names[name] = struct{}{}
				}
			}
			capacity = len(names)
		}
		group.Items = make(map[string]cache_types.ResourceWithTTL, capacity)
		versions := make(map[string]string, capacity)
		for name, entry := range entries {
			if entry.resource == nil {
				continue
			}
			version, err := resourceContentVersion(entry.resource)
			if err != nil {
				return nil, err
			}
			group.Items[name] = cache_types.ResourceWithTTL{Resource: entry.resource}
			versions[name] = version
		}
		if typeURL == typeurl.Endpoint {
			// EDS also needs empty CLAs for Clusters without desired assignments.
			// Project directly from Clusters, using the destination map to deduplicate
			// shared EDS service names and preserve explicit CLAs. A per-name Cluster
			// scan would make a full snapshot quadratic. Never change desired state.
			for clusterName, entry := range state.resources[typeurl.Cluster] {
				if entry.resource == nil {
					continue
				}
				name := clusterEndpointName(clusterName, typedResource[*envoy_config_cluster.Cluster](entry.resource))
				if name == "" {
					continue
				}
				if _, exists := group.Items[name]; exists {
					continue
				}
				resource := &envoy_config_endpoint.ClusterLoadAssignment{ClusterName: name}
				version, err := resourceContentVersion(resource)
				if err != nil {
					return nil, err
				}
				group.Items[name] = cache_types.ResourceWithTTL{Resource: resource}
				versions[name] = version
			}
		}
		if len(group.Items) == 0 {
			group.Items = nil
			versions = nil
		}
		var revertContext string
		if generation := state.typeStates[typeURL].revertGeneration; generation != 0 {
			// Identical contents from before a revert are not its corrective
			// publication. Force a new wire version even for a stream still at A.
			revertContext = fmt.Sprintf("revert:%d", generation)
		}
		group.Version = c.resourceVersion(typeURL, versions, versionContext, revertContext)
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
	comp *completion.Completion
	err  error
}

// SetSnapshot serializes publication and hands off responses only after both
// cache locks have been released.
func (c *cacheImpl) SetSnapshot(ctx context.Context, nodeID string, snapshot cache.ResourceSnapshot) error {
	c.mutex.Lock()
	if c.getNodeState(nodeID) == nil {
		c.mutex.Unlock()
		return fmt.Errorf("unknown xDS node %q", nodeID)
	}
	err := c.SnapshotCache.SetSnapshot(ctx, nodeID, snapshot)
	// Collect even on error: go-control-plane may already have installed the
	// snapshot and queued some responses before failing a later delivery.
	deliveries := c.collectResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	return err
}

// generationWait describes one ACK/NACK wait. generation is the snapshot
// boundary needed to cover the required resource revisions, or the current
// published boundary for a whole-TypeURL wait.
type generationWait struct {
	callback   func(error)
	generation callbacks.Generation
	scope      callbacks.ResourceScope
}

type typeURLWaits = typeurl.Map[generationWait]

// resourceTransaction owns one atomic cache mutation. The cache, context and
// node are fixed when the transaction starts, while response delivery and
// completion work is accumulated for execution after mutex is released.
type resourceTransaction struct {
	cache  *cacheImpl
	ctx    context.Context
	nodeID string

	// state is looked up once while acquiring the cache lock. Known nodes keep
	// the same state for the lifetime of the cache.
	state *nodeState

	// generation is reserved for this mutation, including corrective reverts.
	// Only API mutations also use it as the changed entries' TransactionID.
	generation            callbacks.Generation
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
		state:  c.getNodeState(nodeID),
	}
}

// nextResourceGenerationLocked is the shared source of mutation generations,
// resource revisions, and API transaction identities. Failed attempts may leave
// gaps in the sequence, but never rewind it. Caller must hold c.mutex.
func (c *cacheImpl) nextResourceGenerationLocked() callbacks.Generation {
	c.resourceGeneration++
	return c.resourceGeneration
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
	if tx.updateErr == nil && len(tx.listenerChanges) > 0 &&
		c.listenerObserver != nil && c.listenerObserver.ApplyCommittedChanges(tx.nodeID, tx.listenerChanges) {
		// Detach while holding the cache lock. A new policy update can
		// register a wait after a listener is re-added, even if its
		// resource revision predates this removal.
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
	for _, immediate := range tx.immediateCompletions {
		// Resource-level acceptance proves only this wait, not the other names
		// in older generations of the same TypeURL.
		immediate.comp.Complete(immediate.err)
	}
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
			owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, wait.generation, wait.scope)
			comp := wg.AddCompletionWithCallback(owner, wait.callback)
			version := snapshot.GetVersion(typeURL.URL())
			registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, version, false)
			if !registered {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp: comp, err: err,
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
	state := c.getNodeState(nodeID)

	for typeURL, wait := range waits.All() {
		wait.scope = wait.scope.WithRevisions(func(name string) callbacks.Revision { return state.resourceWaitEntry(typeURL, name).revision })
		owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, wait.generation, wait.scope)
		comp := wg.AddCompletionWithCallback(owner, wait.callback)
		registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, "", true)
		if !registered {
			immediateCompletions = append(immediateCompletions, immediateCompletion{
				comp: comp, err: err,
			})
			continue
		}
		completions.Insert(comp)
	}
	return completions, immediateCompletions
}

type finalizedCompletion struct {
	typeURL    typeurl.Index
	generation callbacks.Generation
	err        error
}

// snapshotTypesChangedBy includes snapshot companions of changed parent types.
// Both zero and initialized-empty sets mean that no resource types changed.
func snapshotTypesChangedBy(changedTypeURLs typeurl.Set) typeurl.Set {
	result := changedTypeURLs
	if changedTypeURLs.Has(typeurl.Listener) {
		result = result.Union(listenerDependentTypeURLs)
	}
	if changedTypeURLs.Has(typeurl.Cluster) {
		result = result.Union(clusterDependentTypeURLs)
	}
	return result
}

// publishSnapshotLocked constructs and installs a snapshot for an accepted
// mutation. The caller holds c.mutex; callbacks are completed after unlocking.
func (c *cacheImpl) publishSnapshotLocked(ctx context.Context, nodeID string, publication snapshotPublication) ([]finalizedCompletion, error) {
	state := c.getNodeState(nodeID)
	oldSnapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	newSnapshot, err := c.generateSnapshotForUpdate(state)
	if err != nil {
		return nil, err
	}

	// SetSnapshot may synchronously queue responses. Capture this snapshot and
	// generation in their context so delayed delivery cannot associate them
	// with a newer publication. Commit callback metadata only after installation.
	err = c.SnapshotCache.SetSnapshot(callbacks.WithSnapshotPublication(ctx, publication.generation, newSnapshot), nodeID, newSnapshot)
	if err != nil {
		// Ignore delivery errors if the intended snapshot was installed.
		currentSnapshot, getErr := c.SnapshotCache.GetSnapshot(nodeID)
		// SetSnapshot stores the exact snapshot object. Equal content versions
		// alone are not installation evidence.
		committed := getErr == nil && currentSnapshot == newSnapshot
		if !committed {
			return nil, err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}
	// Watch responses remain in Cilium's relays until after this publication
	// finishes, so expose the snapshot to callbacks only once it is committed.
	c.completionCbs.SetPublishedSnapshot(nodeID, newSnapshot)

	state.snapshotGeneration = publication.generation
	for typeURL, rollback := range publication.resourceTypes.All() {
		if rollback.empty() {
			continue
		}
		versionChanged := oldSnapshot == nil ||
			oldSnapshot.GetVersion(typeURL.URL()) != newSnapshot.GetVersion(typeURL.URL())
		if !versionChanged {
			state.rollbacks.release(state, rollback)
			continue
		}
		state.rollbacks.retainUnsentLocked(c, state, typeURL, publication.generation, rollback, newSnapshot)
	}
	if oldSnapshot == nil {
		// Waits registered before a baseline exists can concern types outside
		// this mutation. Bind all of them to the newly installed full snapshot.
		for typeURL := range typeurl.Indices() {
			if !publication.resourceTypes.Has(typeURL) {
				publication.resourceTypes.Set(typeURL, rollbackResources{})
			}
		}
	}
	// Do not preallocate: most publications have no immediately satisfied waits,
	// so reserving space here adds allocations to the common churn path.
	var finalized []finalizedCompletion
	for typeURL := range publication.resourceTypes.Keys() {
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
// resource names and transaction-fenced reverts. Changed transactions publish a
// snapshot before returning; published maps remain immutable.
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
	if tx.state == nil {
		c.mutex.Unlock()
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	rollback, err := tx.applyResourcesLocked(mutations, wg, updatedTypeURLs, tracking)
	if err != nil {
		tx.updateErr = err
	}
	tx.complete()
	return rollback, err
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
	if tx.state == nil {
		c.mutex.Unlock()
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	defer tx.complete()

	// Do not wait for network policy ACK if there are no NPDS listeners.
	if typeURL == typeurl.NetworkPolicy && wg != nil && c.listenerObserver != nil && !c.listenerObserver.HasNPDSListeners(nodeID) {
		tx.addAcceptedCallback(wg, callback)
		wg = nil
	}

	previous := tx.state.resources[typeURL][name]
	if previous.resource == resource ||
		(previous.resource != nil && resource != nil && xds.ResourceEqual(previous.resource, resource)) {
		if wg == nil {
			return nil, nil
		}
		// Use the canonical cache pointer for semantic no-ops, so checking ACK
		// evidence does not repeat the comparison against a fresh protobuf.
		waitEntry := tx.state.resourceWaitEntry(typeURL, name)
		if tx.state.resourceGeneration == 0 && resource == nil ||
			c.completionCbs.ResourceAccepted(nodeID, typeURL, name, previous.resource, previous.resource != nil, waitEntry.revision) {
			// A pristine known node has no resource update to acknowledge. After
			// mutations, a removal can still need ACK evidence even if its tombstone
			// has been pruned (notably for named EDS/RDS/SDS resources).
			tx.addAcceptedCallback(wg, callback)
			return nil, nil
		}
		var waits typeURLWaits
		revision := waitEntry.revision
		waits.Set(typeURL, generationWait{callback: callback, generation: callbacks.Generation(0).MaxRevision(revision), scope: callbacks.SingleResourceScope(name, revision)})
		tx.awaitCurrentVersionLocked(wg, waits)
		return nil, nil
	}

	// Record listener changes for the observer when the transaction completes.
	if typeURL == typeurl.Listener {
		tx.listenerChanges = []ListenerChange{{
			Previous: typedResource[*envoy_config_listener.Listener](previous.resource),
			Current:  typedResource[*envoy_config_listener.Listener](resource),
		}}
	}
	inverse := singleResource(typeURL, name, previous)
	tx.generation = c.nextResourceGenerationLocked()
	var changes resourceChanges
	changes.add(typeURL, name, previous, resourceEntry{resource: resource, revision: tx.generation.Revision(), transaction: tx.generation.TransactionID()})

	accepted := false
	var changedWaits typeURLWaits
	if wg != nil {
		accepted = c.completionCbs.ChangedResourceAccepted(
			nodeID, typeURL, name,
			previous.resource, previous.resource != nil,
			resource, resource != nil,
			previous.revision,
		)
		if !accepted {
			changedWaits.Set(typeURL, generationWait{callback: callback, generation: tx.generation, scope: callbacks.SingleResourceScope(name, tx.generation.Revision())})
		}
	}
	if err := tx.updateResourceChangesLocked(changes, resourceUpdateOptions{
		inverse:  inverse,
		waits:    changedWaits,
		tracking: tracking,
	}, wg); err != nil {
		return nil, err
	}
	if accepted {
		tx.addAcceptedCallback(wg, callback)
	}
	if tracking == callerAndResponseRollbackTracking {
		return tx.state.rollbacks.newCallerLocked(&tx, inverse), nil
	}
	return nil, nil
}

// applyResourcesLocked allocates generations and constructs transaction-fenced
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
	changes, changedTypeURLs, inverse := state.prepareResourceMutation(mutations, c.resourceGeneration+1)
	if state.resourceGeneration == 0 && changedTypeURLs.Empty() {
		for _, callback := range updatedTypeURLs.All() {
			tx.addAcceptedCallback(wg, callback)
		}
		return nil, nil
	}
	var unchangedWaits typeURLWaits
	if changedTypeURLs.Empty() {
		if wg == nil || updatedTypeURLs.Empty() {
			return nil, nil
		}
		for typeURL, callback := range updatedTypeURLs.All() {
			wait, accepted := tx.mutationWaitLocked(typeURL, mutations, inverse)
			if accepted {
				tx.addAcceptedCallback(wg, callback)
				continue
			}
			wait.callback = callback
			unchangedWaits.Set(typeURL, wait)
		}
		tx.awaitCurrentVersionLocked(wg, unchangedWaits)
		return nil, nil
	}

	tx.generation = c.nextResourceGenerationLocked()

	var changedWaits typeURLWaits
	if wg != nil {
		dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
		// Acceptance and named scopes serve caller waits only. Response-owned
		// NACK rollback is prepared independently below, even without a WaitGroup.
		for typeURL, callback := range updatedTypeURLs.All() {
			wait, accepted := tx.mutationWaitLocked(typeURL, mutations, inverse)
			if accepted {
				tx.addAcceptedCallback(wg, callback)
				continue
			}
			wait.callback = callback
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
		inverse:  inverse,
		waits:    changedWaits,
		tracking: tracking,
	}, wg)
	if err != nil {
		return nil, err
	}

	if inverse.len(typeurl.Listener) > 0 {
		tx.listenerChanges = committedListenerChanges(changes)
	}

	if tracking == callerAndResponseRollbackTracking {
		return tx.state.rollbacks.newCallerLocked(tx, inverse), nil
	}
	return nil, nil
}

// HandleNACK uses the same transaction boundary as API mutations. Selection is
// inside the cache lock, and the entire correction is published once. complete
// delivers responses and invokes callbacks only after releasing that lock.
func (c *cacheImpl) HandleNACK(nodeID string, process func(callbacks.RevertBatch) error) error {
	tx := c.beginResourceTransaction(context.Background(), nodeID)
	defer tx.complete()
	return process(tx.revertLocked)
}

// revertLocked composes cache-owned inverses into one prepared mutation. Caller
// rollback uses the same path with a single lifecycle. rollbacks are newest
// first; no lifecycle method is called which would take the cache lock again.
func (tx *resourceTransaction) revertLocked(rollbacks []Rollback) error {
	c, state := tx.cache, tx.state
	changes, err := state.rollbacks.prepareRevertLocked(tx, rollbacks)
	if err != nil {
		return err
	}

	if !changes.empty() {
		c.logger.Debug("Reverting resource changes", logfields.NodeID, tx.nodeID)
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
	state.rollbacks.finishRevertLocked(state, rollbacks, err)

	if err == nil {
		tx.listenerChanges = committedListenerChanges(changes)
	} else {
		c.logger.Error("Failed to revert resource changes",
			logfields.NodeID, tx.nodeID,
			logfields.Error, err)
	}
	return err
}

// resourceMutationWait collects only unsatisfied names and their ACK-wait
// generation in one traversal. ACK evidence for unchanged names remains valid
// when another name in the same bulk TypeURL changes: waiting for those names
// again could strand the caller if subsequent responses cover only the changes.
// An absent mutation deliberately waits for the whole published resource type.
func resourceMutationWait[V interface {
	proto.Message
	comparable
}](completionCbs *callbacks.CompletionCallbacks, nodeID string, typeURL typeurl.Index, current map[string]resourceEntry, removed, upserted map[string]V, inverse resources, publishedGeneration, revertGeneration callbacks.Generation) (generationWait, bool) {
	var wait generationWait
	if len(removed) == 0 && len(upserted) == 0 {
		wait.generation = publishedGeneration
		return wait, false
	}
	// Before any ACK, every name must wait. Avoid acquiring the callback lock
	// for each resource merely to rediscover the same absence of ACK evidence.
	hasAcceptance := completionCbs.HasResourceAcceptance(nodeID, typeURL)
	accepted := true
	waitEntry := func(name string) resourceEntry {
		entry := current[name]
		if entry.resource == nil && entry.transaction.IsZero() {
			entry.revision = revertGeneration.Revision()
		}
		return entry
	}
	addPending := func(name string) {
		revision := waitEntry(name).revision
		wait.scope.Insert(name, revision)
		wait.generation = wait.generation.MaxRevision(revision)
		accepted = false
	}
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		if !hasAcceptance || !completionCbs.ResourceAccepted(nodeID, typeURL, name, nil, false, waitEntry(name).revision) {
			addPending(name)
		}
	}
	for name, resource := range upserted {
		if !hasAcceptance {
			addPending(name)
			continue
		}
		// Typed nil upserts remove resources, just as in prepareResourceMap.
		desired := resourceValue(resource)
		entry := waitEntry(name)
		previous := entry.resource
		var resourceAccepted bool
		if _, changed := inverse.get(typeURL, name); changed {
			resourceAccepted = completionCbs.ChangedResourceAccepted(nodeID, typeURL, name,
				previous, previous != nil, desired, desired != nil, entry.revision)
		} else {
			// Preparation already established semantic equality for this name,
			// including mixed transactions. Reuse its canonical pointer rather
			// than comparing the fresh protobuf a second time.
			resourceAccepted = completionCbs.ResourceAccepted(nodeID, typeURL, name, previous, previous != nil, entry.revision)
		}
		if !resourceAccepted {
			addPending(name)
		}
	}
	return wait, accepted
}

func (tx *resourceTransaction) mutationWaitLocked(typeURL typeurl.Index, mutations ResourceMutations, inverse resources) (generationWait, bool) {
	c := tx.cache
	state := tx.state
	current := state.resourceEntries(typeURL)
	publishedGeneration := state.generationForType(typeURL)
	revertGeneration := state.typeStates[typeURL].revertGeneration
	switch typeURL {
	case typeurl.Listener:
		return resourceMutationWait(c.completionCbs, tx.nodeID, typeURL, current, mutations.Removed.Listeners, mutations.Upserted.Listeners, inverse, publishedGeneration, revertGeneration)
	case typeurl.Route:
		return resourceMutationWait(c.completionCbs, tx.nodeID, typeURL, current, mutations.Removed.Routes, mutations.Upserted.Routes, inverse, publishedGeneration, revertGeneration)
	case typeurl.Cluster:
		return resourceMutationWait(c.completionCbs, tx.nodeID, typeURL, current, mutations.Removed.Clusters, mutations.Upserted.Clusters, inverse, publishedGeneration, revertGeneration)
	case typeurl.Endpoint:
		return resourceMutationWait(c.completionCbs, tx.nodeID, typeURL, current, mutations.Removed.Endpoints, mutations.Upserted.Endpoints, inverse, publishedGeneration, revertGeneration)
	case typeurl.Secret:
		return resourceMutationWait(c.completionCbs, tx.nodeID, typeURL, current, mutations.Removed.Secrets, mutations.Upserted.Secrets, inverse, publishedGeneration, revertGeneration)
	default:
		return generationWait{generation: publishedGeneration}, false
	}
}

// generateSnapshotForUpdate is shared by every production mutation.
func (c *cacheImpl) generateSnapshotForUpdate(state *nodeState) (cache.ResourceSnapshot, error) {
	snapshot, err := c.generateSnapshotFromState(state)
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

// resourceUpdateOptions describes rollback ownership and ACK waits for a
// prepared mutation. Its zero value is a compensating update with no new
// rollback ownership or ACK waits; normal updates explicitly select tracking.
type resourceUpdateOptions struct {
	inverse  resources
	waits    typeURLWaits
	tracking rollbackTracking
}

// updateResourceChangesLocked commits one prepared mutation and publishes its
// snapshot before returning. Caller rollback tracking retains the inverse
// through publication; the lifecycle is created only after this succeeds.
// Caller must hold c.mutex; post-lock work is kept on tx.
func (tx *resourceTransaction) updateResourceChangesLocked(changes resourceChanges, options resourceUpdateOptions, wg *completion.WaitGroup) error {
	c := tx.cache
	state := tx.state
	changedTypeURLs := changes.typeURLs()
	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
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
	oldResourceGeneration := state.resourceGeneration
	var previousReverts typeurl.Slots[callbacks.Generation]
	if options.tracking == noRollbackTracking {
		// Only caller- or response-driven reverts use noRollbackTracking.
		// Record their fresh generation for corrective versions and absence waits.
		for typeURL := range changedTypeURLs.Members() {
			previousReverts[typeURL] = state.typeStates[typeURL].revertGeneration
			state.typeStates[typeURL].revertGeneration = tx.generation
		}
	}
	state.commitResourceMutation(changes)
	if checkStrictConsistency {
		state.strictRefs.apply(strictChanges, 1)
	}
	if options.tracking == callerAndResponseRollbackTracking {
		state.rollbacks.updateInverseOwners(state, options.inverse, tx.generation.TransactionID(), 1)
	}
	completions, immediateCompletions := c.registerPrepublicationCompletions(
		tx.nodeID, wg, options.waits)
	publication := snapshotPublication{generation: tx.generation}
	if options.tracking != noRollbackTracking {
		publication.resourceTypes = state.rollbacks.mergePending(state, publication.resourceTypes, changedTypeURLs, options.inverse, tx.generation.TransactionID())
	}
	// Add finalization-only entries after building rollbacks, which omits empty
	// inverses. Preserve any rollback already stored for the same type.
	for typeURL := range typeurl.Indices() {
		if !publication.resourceTypes.Has(typeURL) && (dirtyTypeURLs.Has(typeURL) || options.waits.Has(typeURL)) {
			publication.resourceTypes.Set(typeURL, rollbackResources{})
		}
	}
	finalized, err := c.publishSnapshotLocked(tx.ctx, tx.nodeID, publication)
	deliveries := c.collectResponseDeliveriesLocked()
	if err != nil {
		if options.tracking == noRollbackTracking {
			for typeURL := range changedTypeURLs.Members() {
				state.typeStates[typeURL].revertGeneration = previousReverts[typeURL]
			}
		}
		if options.tracking == callerAndResponseRollbackTracking {
			state.rollbacks.releaseInverse(state, options.inverse, tx.generation.TransactionID())
		}
		// Prepared previous entries also recover failed rollback publications,
		// without allocating inverse maps or materializing a singleton.
		if !changes.empty() {
			change := changes.first
			state.resources.commitEntry(change.typeURL, change.name, change.previous)
		}
		for _, change := range changes.more {
			state.resources.commitEntry(change.typeURL, change.name, change.previous)
		}
		if checkStrictConsistency {
			state.strictRefs.apply(strictChanges, -1)
		}
		state.rollbacks.releaseSet(state, publication.resourceTypes)
		state.resourceGeneration = oldResourceGeneration
	} else {
		state.resourceGeneration = tx.generation
		state.rollbacks.pruneUnownedRemovalsLocked(tx, changes, options)
	}
	tx.deliveries = deliveries
	tx.finalized = finalized
	tx.registeredCompletions.Merge(completions)
	tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
	tx.updateErr = err
	return err
}

// awaitCurrentVersionLocked registers no-op waits against published state, or
// desired revisions if no baseline exists. Caller holds c.mutex; callbacks
// are completed after unlocking.
func (tx *resourceTransaction) awaitCurrentVersionLocked(wg *completion.WaitGroup, waits typeURLWaits) {
	if wg == nil || waits.Empty() {
		return
	}
	c := tx.cache
	currentSnapshot, err := c.SnapshotCache.GetSnapshot(tx.nodeID)
	var registered set.Set[*completion.Completion]
	var immediateCompletions []immediateCompletion
	if err != nil {
		// Before the first publication or after ClearSnapshot, an unchanged
		// resource still has authoritative desired state. Await its next
		// publication rather than failing or forcing snapshot construction.
		registered, immediateCompletions = c.registerPrepublicationCompletions(tx.nodeID, wg, waits)
	} else {
		registered, immediateCompletions = c.registerGenerationCompletions(tx.nodeID, currentSnapshot, wg, waits)
	}
	tx.registeredCompletions.Merge(registered)
	tx.immediateCompletions = append(tx.immediateCompletions, immediateCompletions...)
}

func (c *cacheImpl) ClearSnapshot(nodeID string) {
	c.mutex.Lock()
	c.SnapshotCache.ClearSnapshot(nodeID)
	c.completionCbs.SetPublishedSnapshot(nodeID, nil)
	// Clearing delivery state does not forget a known consumer or its desired
	// resources. A later watch republishes those resources through the normal
	// publication path.
	var cancels []func()
	if state := c.getNodeState(nodeID); state != nil {
		for _, watches := range state.openWatches.All() {
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
				snapshot, _ := c.SnapshotCache.GetSnapshot(response.GetRequest().GetNode().GetId())
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

func (c *cacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	if request == nil {
		return nil, errors.New("nil xDS request")
	}
	nodeID := request.GetNode().GetId()
	state := c.getNodeState(nodeID)
	if state == nil {
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	if sub == nil {
		return c.SnapshotCache.CreateWatch(request, sub, respChan)
	}
	typeURL, supported := typeurl.FromURL(request.GetTypeUrl())
	if !supported {
		// Unknown protocol types are outside Cilium's fixed ADS resource set.
		// Preserve go-control-plane behavior without creating internal tracking
		// state which could never be addressed by an indexed mutation.
		return c.SnapshotCache.CreateWatch(request, sub, respChan)
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
	var finalized []finalizedCompletion
	if _, getErr := c.SnapshotCache.GetSnapshot(nodeID); getErr != nil {
		// No snapshot exists, create one from the desired state.
		finalized, err = c.publishSnapshotLocked(context.Background(), nodeID, snapshotPublication{
			generation: state.resourceGeneration,
		})
		if err != nil {
			deliveries := c.collectResponseDeliveriesLocked()
			c.mutex.Unlock()
			c.deliverResponses(deliveries)
			return nil, err
		}
	}
	// Register before calling go-control-plane: CreateWatch may immediately
	// queue a response rather than establish a deferred watch. Its relay keeps
	// that response buffered until we retire the watch and release the locks.
	// Tracking independent named watches does not override strict ADS delivery
	// rules: go-control-plane withholds a named response unless the request names
	// include every resource of that type in the snapshot. Disjoint subscriptions
	// on separate streams can therefore be tracked without receiving responses.
	watch := c.addTrackedWatchLocked(state, request, typeURL, respChan)
	watch.cancel, err = c.SnapshotCache.CreateWatch(request, sub, watch.relay.inner)
	if err != nil {
		c.removeTrackedWatchLocked(watch)
	}
	deliveries := c.collectResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	c.completeFinalized(nodeID, finalized)
	if err != nil {
		return nil, err
	}
	return func() { c.cancelTrackedWatch(watch) }, nil
}

func (c *cacheImpl) GetResource(nodeID string, typeURL typeurl.Index, resourceName string) cache_types.Resource {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.getNodeState(nodeID).getResource(typeURL, resourceName)
}

func (c *cacheImpl) Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener] {
	return func(yield func(string, *envoy_config_listener.Listener) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		state := c.getNodeState(nodeID)
		if state == nil {
			return
		}
		for name, entry := range state.resources[typeurl.Listener] {
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
		state := c.getNodeState(nodeID)
		if state == nil {
			return
		}
		for name, entry := range state.resources[typeurl.Route] {
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
		state := c.getNodeState(nodeID)
		if state == nil {
			return
		}
		for name, entry := range state.resources[typeurl.NetworkPolicy] {
			if entry.resource != nil && !yield(name, typedResource[*cilium.NetworkPolicy](entry.resource)) {
				return
			}
		}
	}
}
