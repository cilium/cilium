// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/davecgh/go-spew/spew"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
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
	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = "type.googleapis.com/cilium.NetworkPolicy"
	NetworkPolicyHostsTypeURL = "type.googleapis.com/cilium.NetworkPolicyHosts"
	logFieldComponent         = "component"
)

type RevertFunc = callbacks.RevertFunc

// SnapshotGenerator constructs the immutable snapshot which represents the
// latest staged resources. Keeping generation behind this callback lets the
// cache postpone protobuf marshaling and version hashing until Envoy has a
// watch which can consume the result.
type SnapshotGenerator func(resources *xds.Resources, previous cache.ResourceSnapshot, changedTypeURLs map[string]struct{}) (cache.ResourceSnapshot, error)

type Cache interface {
	cache.SnapshotCache

	GetVersion(resources *xds.Resources) string
	GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error)
	// GenerateSnapshotIncrementally reuses immutable state from previous for
	// resource types outside changedTypeURLs. A nil change set requests a full
	// snapshot; a non-nil empty set returns the previous snapshot unchanged.
	GenerateSnapshotIncrementally(resources *xds.Resources, previous cache.ResourceSnapshot, changedTypeURLs map[string]struct{}, logger *slog.Logger) (cache.ResourceSnapshot, error)
	// UpdateResources stages the newest immutable resource state. Snapshot
	// construction is deferred until an affected watch is already open or the
	// next affected CreateWatch call arrives.
	UpdateResources(ctx context.Context, nodeID string, generation uint64, resources *xds.Resources, changedTypeURLs map[string]struct{}, generator SnapshotGenerator, wg *completion.WaitGroup, updatedTypeURLs map[string]func(err error), revertFunc RevertFunc) error
	// AwaitCurrentVersion registers completions against the current snapshot
	// without publishing it again.
	AwaitCurrentVersion(nodeID string, wg *completion.WaitGroup, typeURLs map[string]func(err error)) error
	// SetResources transfers resources to the cache as immutable desired state.
	SetResources(nodeID string, resources *xds.Resources)
	// GetAllResources returns cache-owned immutable state. Callers must use
	// copy-on-write rather than mutate the returned Resources or its contents.
	GetAllResources(nodeID string) *xds.Resources
	AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
}

type cacheImpl struct {
	cache.SnapshotCache

	// mutex protects accesses to the configuration resources below.
	mutex *lock.RWMutex
	// resourcesInSnapshot holds the latest immutable desired resources keyed by
	// nodeID. They may still be waiting for lazy snapshot finalization.
	resourcesInSnapshot map[string]*xds.Resources
	// stagedSnapshots holds resource generations which have not yet been
	// finalized into a go-control-plane snapshot. At most one entry is retained
	// per node; subsequent updates replace its resources and merge dirty types.
	stagedSnapshots map[string]*stagedSnapshot
	// snapshotGenerations records the generation associated with the current
	// snapshot for each node. AwaitCurrentVersion uses it to attach a no-op
	// update to the response which actually carries that snapshot.
	snapshotGenerations map[string]uint64
	// openWatches tracks the precise resource types which can consume a newly
	// finalized snapshot. go-control-plane exposes only a total watch count, so
	// responses are relayed through cache-owned channels to retire each watch as
	// soon as it is consumed.
	openWatches   map[watchKey]map[uint64]*trackedWatch
	watchRelays   map[chan cache.Response]*watchRelay
	nextWatchID   uint64
	logger        *slog.Logger
	hasher        hash.Hash32
	completionCbs *callbacks.CompletionCallbacks
}

type stagedSnapshot struct {
	resources          *xds.Resources
	generation         uint64
	changedTypeURLs    map[string]struct{}
	completionTypeURLs map[string]struct{}
	generations        []stagedGeneration
	generator          SnapshotGenerator
}

// stagedGeneration retains only the rollback information needed if multiple
// resource mutations are folded into the same lazily generated response. The
// history is discarded as soon as the staged snapshot is finalized.
type stagedGeneration struct {
	generation      uint64
	changedTypeURLs map[string]struct{}
	revertFunc      RevertFunc
}

type watchKey struct {
	nodeID  string
	typeURL string
}

type watchRelay struct {
	inner   chan cache.Response
	outer   chan cache.Response
	watches map[uint64]*trackedWatch
}

type trackedWatch struct {
	id      uint64
	key     watchKey
	request *cache.Request
	relay   *watchRelay
	cancel  func()
	closed  bool
}

type responseDelivery struct {
	channel   chan cache.Response
	responses []cache.Response
}

var _ Cache = &cacheImpl{}

// ciliumSnapshot implements go-control-plane's ResourceSnapshot interface for
// both Envoy core resources and Cilium-specific xDS resources.
type ciliumSnapshot struct {
	Resources        map[string]cache.Resources
	VersionMap       map[string]map[string]string
	resourceVersions map[string]map[string]string
}

// Ensure ciliumSnapshot implements cache.ResourceSnapshot.
var _ cache.ResourceSnapshot = &ciliumSnapshot{}
var _ interface{ Consistent() error } = &ciliumSnapshot{}

var snapshotResourceTypes = []envoy_resource.Type{
	envoy_resource.EndpointType,
	envoy_resource.ClusterType,
	envoy_resource.RouteType,
	envoy_resource.ListenerType,
	envoy_resource.SecretType,
	NetworkPolicyTypeURL,
	NetworkPolicyHostsTypeURL,
}

func newCiliumSnapshot(resources map[string]cache.Resources, resourceVersions map[string]map[string]string) *ciliumSnapshot {
	w := &ciliumSnapshot{
		Resources:        make(map[string]cache.Resources, len(snapshotResourceTypes)),
		resourceVersions: make(map[string]map[string]string, len(snapshotResourceTypes)),
	}
	for _, typeURL := range snapshotResourceTypes {
		w.Resources[typeURL] = resources[typeURL]
		w.resourceVersions[typeURL] = resourceVersions[typeURL]
	}
	return w
}

func (w *ciliumSnapshot) GetVersion(typeURL string) string {
	group, ok := w.Resources[typeURL]
	if !ok {
		return ""
	}
	return group.Version
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

func (w *ciliumSnapshot) GetResourcesAndTTL(typeURL string) map[string]cache_types.ResourceWithTTL {
	group, ok := w.Resources[typeURL]
	if !ok {
		return nil
	}
	return group.Items
}

func (w *ciliumSnapshot) ConstructVersionMap() error {
	if w == nil {
		return fmt.Errorf("missing snapshot")
	}
	if w.VersionMap != nil {
		return nil
	}
	if w.resourceVersions != nil {
		w.VersionMap = make(map[string]map[string]string, len(w.resourceVersions))
		for typeURL, versions := range w.resourceVersions {
			if len(versions) > 0 {
				w.VersionMap[typeURL] = maps.Clone(versions)
			}
		}
		return nil
	}

	w.VersionMap = make(map[string]map[string]string, len(w.Resources))
	for typeURL, group := range w.Resources {
		if len(group.Items) == 0 {
			continue
		}
		w.VersionMap[typeURL] = make(map[string]string, len(group.Items))
		for name, resource := range group.Items {
			marshaledResource, err := cache.MarshalResource(resource.Resource)
			if err != nil {
				return err
			}
			w.VersionMap[typeURL][name] = cache.HashResource(marshaledResource)
		}
	}
	return nil
}

func (w *ciliumSnapshot) GetVersionMap(typeURL string) map[string]string {
	if w == nil || w.VersionMap == nil {
		return nil
	}
	return w.VersionMap[typeURL]
}

func (w *ciliumSnapshot) Consistent() error {
	if w == nil {
		return fmt.Errorf("nil snapshot")
	}

	var resourceGroups [cache_types.UnknownType]cache.Resources
	for typeURL, resources := range w.Resources {
		responseType := cache.GetResponseType(envoy_resource.Type(typeURL))
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

	return &cacheImpl{
		SnapshotCache:       snapshotCache,
		mutex:               &lock.RWMutex{},
		resourcesInSnapshot: make(map[string]*xds.Resources),
		stagedSnapshots:     make(map[string]*stagedSnapshot),
		snapshotGenerations: make(map[string]uint64),
		openWatches:         make(map[watchKey]map[uint64]*trackedWatch),
		watchRelays:         make(map[chan cache.Response]*watchRelay),
		logger:              logger,
		hasher:              fnv.New32a(),
		completionCbs:       callbacks.NewCompletionCallbacks(logger),
	}
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

func (c *cacheImpl) GetVersion(resources *xds.Resources) string {
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

func edsClusterReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, cluster := range resources.Clusters {
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

func rdsListenerReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.Listeners {
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

func listenerClusterReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.Listeners {
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

func sdsReferenceVersionContext(resources *xds.Resources) string {
	refs := make(map[string]map[string]struct{})
	for name, listener := range resources.Listeners {
		for _, filterChain := range listener.GetFilterChains() {
			addDownstreamTLSContextSDSReferences(refs, name, downstreamTLSContextFromTransportSocket(filterChain.GetTransportSocket()))
		}
	}
	for name, cluster := range resources.Clusters {
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

func (c *cacheImpl) resourceVersion(typeURL string, resourceVersions map[string]string, versionContext ...string) string {
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
	return c.hash(map[string]string{typeURL: sb.String()})
}

func (c *cacheImpl) resourceVersions(typeURL string, resources map[string]cache_types.Resource, versionContext ...string) (string, map[string]string, error) {
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

func (c *cacheImpl) updateResourceVersions(typeURL string, resources map[string]cache_types.Resource, previous cache.Resources, previousVersions map[string]string, versionContext ...string) (cache.Resources, map[string]string, error) {
	items := maps.Clone(previous.Items)
	versions := maps.Clone(previousVersions)

	for name := range items {
		if _, exists := resources[name]; !exists {
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
		if items == nil {
			items = make(map[string]cache_types.ResourceWithTTL)
		}
		if versions == nil {
			versions = make(map[string]string)
		}
		items[name] = cache_types.ResourceWithTTL{Resource: resource}
		versions[name] = version
	}

	return cache.Resources{
		Version: c.resourceVersion(typeURL, versions, versionContext...),
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

func snapshotResourcesForType(resources *xds.Resources, typeURL string) map[string]cache_types.Resource {
	if typeURL == envoy_resource.EndpointType {
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
	case envoy_resource.ClusterType:
		return snapshotResourceMap(resources.Clusters)
	case envoy_resource.RouteType:
		return snapshotResourceMap(resources.Routes)
	case envoy_resource.ListenerType:
		return snapshotResourceMap(resources.Listeners)
	case envoy_resource.SecretType:
		return snapshotResourceMap(resources.Secrets)
	case NetworkPolicyTypeURL:
		return snapshotResourceMap(resources.NetworkPolicies)
	case NetworkPolicyHostsTypeURL:
		return snapshotResourceMap(resources.NetworkPolicyHosts)
	default:
		return nil
	}
}

func snapshotVersionContext(resources *xds.Resources, typeURL string) string {
	switch typeURL {
	case envoy_resource.EndpointType:
		// Envoy creates one EDS subscription per EDS-backed cluster. A new
		// parent can request a dependent resource that the ADS stream has already
		// seen at the current version, so go-control-plane may open the new watch
		// without replaying the cached resource. Include the parent reference sets
		// in dependent resource versions so new subscriptions receive the current
		// resource immediately.
		return edsClusterReferenceVersionContext(resources)
	case envoy_resource.RouteType:
		return rdsListenerReferenceVersionContext(resources)
	case envoy_resource.SecretType:
		return sdsReferenceVersionContext(resources)
	case envoy_resource.ClusterType:
		return listenerClusterReferenceVersionContext(resources)
	default:
		return ""
	}
}

func incrementalSnapshotTypeURLs(changedTypeURLs map[string]struct{}) (map[string]struct{}, bool) {
	if changedTypeURLs == nil {
		return nil, false
	}

	regenerate := maps.Clone(changedTypeURLs)
	for typeURL := range changedTypeURLs {
		if !slices.Contains(snapshotResourceTypes, envoy_resource.Type(typeURL)) {
			return nil, false
		}
	}

	if _, listenersChanged := changedTypeURLs[envoy_resource.ListenerType]; listenersChanged {
		regenerate[envoy_resource.RouteType] = struct{}{}
		regenerate[envoy_resource.ClusterType] = struct{}{}
		regenerate[envoy_resource.SecretType] = struct{}{}
	}
	if _, clustersChanged := changedTypeURLs[envoy_resource.ClusterType]; clustersChanged {
		regenerate[envoy_resource.EndpointType] = struct{}{}
		regenerate[envoy_resource.SecretType] = struct{}{}
	}

	return regenerate, true
}

func (c *cacheImpl) canGenerateSnapshotIncrementally(previous cache.ResourceSnapshot, changedTypeURLs map[string]struct{}) (*ciliumSnapshot, map[string]struct{}, bool) {
	previousSnapshot, ok := previous.(*ciliumSnapshot)
	if !ok || previousSnapshot == nil || previousSnapshot.resourceVersions == nil {
		return nil, nil, false
	}
	for _, typeURL := range snapshotResourceTypes {
		if _, exists := previousSnapshot.Resources[typeURL]; !exists {
			return nil, nil, false
		}
		if _, exists := previousSnapshot.resourceVersions[typeURL]; !exists {
			return nil, nil, false
		}
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

func (c *cacheImpl) GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	if resources == nil {
		empty := xds.NewResources()
		resources = &empty
	}

	resources = normalizeSnapshotResources(resources)
	versionedResources := make(map[string]cache.Resources, len(snapshotResourceTypes))
	resourceVersions := make(map[string]map[string]string, len(snapshotResourceTypes))
	for _, typeURL := range snapshotResourceTypes {
		resourceMap := snapshotResourcesForType(resources, typeURL)
		version, versions, err := c.resourceVersions(typeURL, resourceMap, snapshotVersionContext(resources, typeURL))
		if err != nil {
			return nil, err
		}
		versionedResources[typeURL] = resourceGroup(version, resourceMap)
		resourceVersions[typeURL] = versions
	}

	return newCiliumSnapshot(versionedResources, resourceVersions), nil
}

func (c *cacheImpl) GenerateSnapshotIncrementally(resources *xds.Resources, previous cache.ResourceSnapshot, changedTypeURLs map[string]struct{}, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	previousSnapshot, regenerate, ok := c.canGenerateSnapshotIncrementally(previous, changedTypeURLs)
	if !ok {
		return c.GenerateSnapshot(resources, logger)
	}
	if len(regenerate) == 0 {
		return previousSnapshot, nil
	}

	if resources == nil {
		empty := xds.NewResources()
		resources = &empty
	}
	resources = normalizeSnapshotResources(resources)

	versionedResources := maps.Clone(previousSnapshot.Resources)
	resourceVersions := maps.Clone(previousSnapshot.resourceVersions)
	for typeURL := range regenerate {
		resourceMap := snapshotResourcesForType(resources, typeURL)
		group, versions, err := c.updateResourceVersions(
			typeURL,
			resourceMap,
			previousSnapshot.Resources[typeURL],
			previousSnapshot.resourceVersions[typeURL],
			snapshotVersionContext(resources, typeURL),
		)
		if err != nil {
			return nil, err
		}
		versionedResources[typeURL] = group
		resourceVersions[typeURL] = versions
	}

	return newCiliumSnapshot(versionedResources, resourceVersions), nil
}

func (c *cacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return c.completionCbs
}

// SetResources stores resources as cache-owned immutable desired state. It
// intentionally does not clone resources; callers transfer ownership when
// calling this method.
func (c *cacheImpl) SetResources(nodeID string, resources *xds.Resources) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourcesInSnapshot[nodeID] = resources
}

type immediateCompletion struct {
	comp                      *completion.Completion
	typeURL                   string
	generation                uint64
	err                       error
	completeUnsentCompletions bool
}

func (c *cacheImpl) registerGenerationCompletions(nodeID string, generation uint64, newSnapshot, oldSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, typeURLs map[string]func(err error), revertFunc RevertFunc) ([]*completion.Completion, []immediateCompletion) {
	completions := make([]*completion.Completion, 0, len(typeURLs))
	immediateCompletions := make([]immediateCompletion, 0, 1)
	if wg != nil && len(typeURLs) > 0 {
		for typeURL, completionCallback := range typeURLs {
			owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, generation)
			comp := wg.AddCompletionWithCallback(owner, completionCallback)
			if typeURL == NetworkPolicyTypeURL && len(newSnapshot.GetResourcesAndTTL(NetworkPolicyTypeURL)) == 0 {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					generation:                generation,
					completeUnsentCompletions: true,
				})
				continue
			}
			version := newSnapshot.GetVersion(typeURL)
			versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
			registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, version, versionChanged, revertFunc)
			if !registered {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					generation:                generation,
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

func (c *cacheImpl) registerStagedGenerationCompletions(nodeID string, generation uint64, resources *xds.Resources, wg *completion.WaitGroup, typeURLs map[string]func(err error), revertFunc RevertFunc) ([]*completion.Completion, []immediateCompletion) {
	completions := make([]*completion.Completion, 0, len(typeURLs))
	immediateCompletions := make([]immediateCompletion, 0, 1)
	if wg == nil || len(typeURLs) == 0 {
		return completions, immediateCompletions
	}

	for typeURL, completionCallback := range typeURLs {
		owner := c.completionCbs.NewTypeGenerationCompletionOwner(nodeID, typeURL, generation)
		comp := wg.AddCompletionWithCallback(owner, completionCallback)
		if typeURL == NetworkPolicyTypeURL && (resources == nil || len(resources.NetworkPolicies) == 0) {
			immediateCompletions = append(immediateCompletions, immediateCompletion{
				comp:                      comp,
				typeURL:                   typeURL,
				generation:                generation,
				completeUnsentCompletions: true,
			})
			continue
		}
		registered, err := c.completionCbs.AddPreparedTypeGenerationCompletion(comp, owner, "", true, revertFunc)
		if !registered {
			immediateCompletions = append(immediateCompletions, immediateCompletion{
				comp:                      comp,
				typeURL:                   typeURL,
				generation:                generation,
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
	typeURL    string
	generation uint64
	err        error
}

func (c *cacheImpl) completeImmediateCompletions(nodeID string, immediateCompletions []immediateCompletion) {
	for _, completion := range immediateCompletions {
		if completion.completeUnsentCompletions {
			c.completionCbs.CompleteCompletionsThroughGeneration(nodeID, completion.typeURL, completion.generation, nil)
		}
		completion.comp.Complete(completion.err)
	}
}

func snapshotTypesChangedBy(changedTypeURLs map[string]struct{}) map[string]struct{} {
	regenerate, ok := incrementalSnapshotTypeURLs(changedTypeURLs)
	if ok {
		return regenerate
	}
	regenerate = make(map[string]struct{}, len(snapshotResourceTypes))
	for _, typeURL := range snapshotResourceTypes {
		regenerate[typeURL] = struct{}{}
	}
	return regenerate
}

// finalizeStagedSnapshotLocked constructs and installs the newest staged
// snapshot for nodeID. The caller must hold c.mutex. Completion resolution is
// returned to the caller so callbacks can run after the cache lock is released.
func (c *cacheImpl) finalizeStagedSnapshotLocked(ctx context.Context, nodeID string) (bool, []finalizedCompletion, error) {
	staged := c.stagedSnapshots[nodeID]
	if staged == nil {
		return false, nil, nil
	}
	if staged.generator == nil {
		return false, nil, fmt.Errorf("missing snapshot generator for node %s", nodeID)
	}

	oldSnapshot, _ := c.SnapshotCache.GetSnapshot(nodeID)
	newSnapshot, err := staged.generator(staged.resources, oldSnapshot, staged.changedTypeURLs)
	if err != nil {
		return false, nil, err
	}

	oldGeneration := c.snapshotGenerations[nodeID]
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
		committed := getErr == nil && !c.AreDifferentSnapshots(currentSnapshot, newSnapshot)
		if !committed {
			c.completionCbs.SetPublishedSnapshot(nodeID, oldGeneration, oldSnapshot)
			return false, nil, err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}

	delete(c.stagedSnapshots, nodeID)
	c.snapshotGenerations[nodeID] = staged.generation
	// Register rollback state only after the snapshot has been installed. An
	// older mutation without a WaitGroup may precede a tracked mutation in the
	// same response, and a NACK must revert both generations. AddTypeGeneration
	// ignores this history when no completion is waiting for the resource type.
	for _, update := range staged.generations {
		for typeURL := range update.changedTypeURLs {
			c.completionCbs.AddTypeGeneration(
				update.generation, "", typeURL, nodeID, true, update.revertFunc)
		}
	}
	finalized := make([]finalizedCompletion, 0, len(staged.completionTypeURLs))
	for typeURL := range staged.completionTypeURLs {
		version := newSnapshot.GetVersion(typeURL)
		versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
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

func (c *cacheImpl) UpdateResources(ctx context.Context, nodeID string, generation uint64, resources *xds.Resources, changedTypeURLs map[string]struct{}, generator SnapshotGenerator, wg *completion.WaitGroup, updatedTypeURLs map[string]func(err error), revertFunc RevertFunc) error {
	dirtyTypeURLs := snapshotTypesChangedBy(changedTypeURLs)
	completions, immediateCompletions := c.registerStagedGenerationCompletions(
		nodeID, generation, resources, wg, updatedTypeURLs, revertFunc)
	// A completion already owns the revert for its resource type. Retain only
	// untracked mutations in the staged history so finalization can attach them
	// to a later tracked response without duplicating hot-path bookkeeping.
	var rollbackTypeURLs map[string]struct{}
	if revertFunc != nil {
		rollbackTypeURLs = dirtyTypeURLs
		if wg != nil && len(updatedTypeURLs) > 0 {
			rollbackTypeURLs = maps.Clone(dirtyTypeURLs)
			for typeURL := range updatedTypeURLs {
				delete(rollbackTypeURLs, typeURL)
			}
		}
	}

	c.mutex.Lock()
	oldResources := c.resourcesInSnapshot[nodeID]
	oldStaged := c.stagedSnapshots[nodeID]
	mergedTypeURLs := maps.Clone(dirtyTypeURLs)
	completionTypeURLs := maps.Clone(dirtyTypeURLs)
	var generations []stagedGeneration
	if oldStaged != nil {
		for typeURL := range oldStaged.changedTypeURLs {
			mergedTypeURLs[typeURL] = struct{}{}
		}
		for typeURL := range oldStaged.completionTypeURLs {
			completionTypeURLs[typeURL] = struct{}{}
		}
		generations = append(generations, oldStaged.generations...)
	}
	for typeURL := range updatedTypeURLs {
		completionTypeURLs[typeURL] = struct{}{}
	}
	c.resourcesInSnapshot[nodeID] = resources
	if len(rollbackTypeURLs) > 0 {
		generations = append(generations, stagedGeneration{
			generation:      generation,
			changedTypeURLs: rollbackTypeURLs,
			revertFunc:      revertFunc,
		})
	}
	c.stagedSnapshots[nodeID] = &stagedSnapshot{
		resources:          resources,
		generation:         generation,
		changedTypeURLs:    mergedTypeURLs,
		completionTypeURLs: completionTypeURLs,
		generations:        generations,
		generator:          generator,
	}

	var finalized []finalizedCompletion
	var err error
	if c.hasOpenWatchLocked(nodeID, mergedTypeURLs) {
		_, finalized, err = c.finalizeStagedSnapshotLocked(ctx, nodeID)
	}
	deliveries := c.collectResponseDeliveriesLocked()
	if err != nil {
		c.resourcesInSnapshot[nodeID] = oldResources
		if oldStaged == nil {
			delete(c.stagedSnapshots, nodeID)
		} else {
			c.stagedSnapshots[nodeID] = oldStaged
		}
	}
	c.mutex.Unlock()
	c.deliverResponses(deliveries)

	if err != nil {
		for _, comp := range completions {
			c.completionCbs.RemoveTypeGenerationCompletion(comp)
		}
		return err
	}
	c.completeFinalized(nodeID, finalized)
	if resources == nil || len(resources.NetworkPolicies) == 0 {
		// With no NPDS resources there may be no policy watch or ACK to resolve
		// older policy waiters. The empty state is still retained for lazy
		// publication if Envoy connects later.
		c.completionCbs.CompleteCompletionsThroughGeneration(
			nodeID, NetworkPolicyTypeURL, generation, nil)
	}
	c.completeImmediateCompletions(nodeID, immediateCompletions)
	return nil
}

// AwaitCurrentVersion registers completions for the requested resource types
// against the versions in the currently published snapshot without publishing
// the snapshot again. The completions attach to an in-flight response, complete
// immediately for an ACKed or NACKed version, or wait for the current version to
// be sent and acknowledged.
func (c *cacheImpl) AwaitCurrentVersion(nodeID string, wg *completion.WaitGroup, typeURLs map[string]func(err error)) error {
	if wg == nil || len(typeURLs) == 0 {
		return nil
	}

	c.mutex.Lock()
	staged := c.stagedSnapshots[nodeID]
	if staged != nil {
		stagedTypeURLs := make(map[string]func(error))
		publishedTypeURLs := make(map[string]func(error))
		for typeURL, callback := range typeURLs {
			if _, changed := staged.changedTypeURLs[typeURL]; changed {
				stagedTypeURLs[typeURL] = callback
			} else {
				publishedTypeURLs[typeURL] = callback
			}
		}
		_, immediateCompletions := c.registerStagedGenerationCompletions(
			nodeID, staged.generation, staged.resources, wg, stagedTypeURLs, nil)
		if len(publishedTypeURLs) == 0 {
			c.mutex.Unlock()
			c.completeImmediateCompletions(nodeID, immediateCompletions)
			return nil
		}
		currentSnapshot, err := c.SnapshotCache.GetSnapshot(nodeID)
		if err != nil {
			c.mutex.Unlock()
			return fmt.Errorf("failed to get current snapshot for node %s: %w", nodeID, err)
		}
		_, publishedImmediate := c.registerGenerationCompletions(
			nodeID, c.snapshotGenerations[nodeID], currentSnapshot, currentSnapshot, wg, publishedTypeURLs, nil)
		c.mutex.Unlock()
		c.completeImmediateCompletions(nodeID, immediateCompletions)
		c.completeImmediateCompletions(nodeID, publishedImmediate)
		return nil
	}

	currentSnapshot, err := c.SnapshotCache.GetSnapshot(nodeID)
	if err != nil {
		c.mutex.Unlock()
		return fmt.Errorf("failed to get current snapshot for node %s: %w", nodeID, err)
	}
	generation := c.snapshotGenerations[nodeID]
	_, immediateCompletions := c.registerGenerationCompletions(nodeID, generation, currentSnapshot, currentSnapshot, wg, typeURLs, nil)
	c.mutex.Unlock()
	c.completeImmediateCompletions(nodeID, immediateCompletions)
	return nil
}

func (c *cacheImpl) ClearSnapshot(nodeID string) {
	c.mutex.Lock()
	c.SnapshotCache.ClearSnapshot(nodeID)
	c.completionCbs.SetPublishedSnapshot(nodeID, 0, nil)
	c.resourcesInSnapshot[nodeID] = &xds.Resources{}
	delete(c.stagedSnapshots, nodeID)
	delete(c.snapshotGenerations, nodeID)
	var cancels []func()
	for key, watches := range c.openWatches {
		if key.nodeID != nodeID {
			continue
		}
		for _, watch := range watches {
			watch.closed = true
			if watch.cancel != nil {
				cancels = append(cancels, watch.cancel)
			}
			c.removeTrackedWatchLocked(watch)
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

func (c *cacheImpl) hasOpenWatchLocked(nodeID string, typeURLs map[string]struct{}) bool {
	for typeURL := range typeURLs {
		if len(c.openWatches[watchKey{nodeID: nodeID, typeURL: typeURL}]) > 0 {
			return true
		}
	}
	return false
}

func (c *cacheImpl) relayForLocked(responseChannel chan cache.Response) *watchRelay {
	if relay := c.watchRelays[responseChannel]; relay != nil {
		return relay
	}
	capacity := cap(responseChannel)
	if capacity < len(snapshotResourceTypes)+1 {
		capacity = len(snapshotResourceTypes) + 1
	}
	relay := &watchRelay{
		inner:   make(chan cache.Response, capacity),
		outer:   responseChannel,
		watches: make(map[uint64]*trackedWatch),
	}
	c.watchRelays[responseChannel] = relay
	return relay
}

func (c *cacheImpl) addTrackedWatchLocked(request *cache.Request, responseChannel chan cache.Response) *trackedWatch {
	c.nextWatchID++
	relay := c.relayForLocked(responseChannel)
	watch := &trackedWatch{
		id:      c.nextWatchID,
		key:     watchKey{nodeID: request.GetNode().GetId(), typeURL: request.GetTypeUrl()},
		request: request,
		relay:   relay,
	}
	watches := c.openWatches[watch.key]
	if watches == nil {
		watches = make(map[uint64]*trackedWatch)
		c.openWatches[watch.key] = watches
	}
	watches[watch.id] = watch
	relay.watches[watch.id] = watch
	return watch
}

func (c *cacheImpl) removeTrackedWatchLocked(watch *trackedWatch) {
	if watch == nil {
		return
	}
	if watches := c.openWatches[watch.key]; watches != nil {
		delete(watches, watch.id)
		if len(watches) == 0 {
			delete(c.openWatches, watch.key)
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
	if watch.closed {
		c.mutex.Unlock()
		return
	}
	watch.closed = true
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
				responses = append(responses, response)
				var matched *trackedWatch
				for _, watch := range relay.watches {
					if watch.request == response.GetRequest() {
						matched = watch
						break
					}
				}
				if matched != nil {
					matched.closed = true
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

func (c *cacheImpl) deliverResponses(deliveries []responseDelivery) {
	for _, delivery := range deliveries {
		for _, response := range delivery.responses {
			delivery.channel <- response
		}
	}
}

func (c *cacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	if request != nil && request.GetTypeUrl() == envoy_resource.SecretType && len(request.GetResourceNames()) == 0 {
		c.logger.Debug("Ignoring empty ADS SDS watch")
		return func() {}, nil
	}
	request = normalizeCustomWildcardRequest(request, sub)
	if request == nil {
		return c.SnapshotCache.CreateWatch(request, sub, respChan)
	}

	nodeID := request.GetNode().GetId()
	typeURL := request.GetTypeUrl()
	c.mutex.Lock()
	var finalized []finalizedCompletion
	if staged := c.stagedSnapshots[nodeID]; staged != nil {
		if _, changed := staged.changedTypeURLs[typeURL]; changed {
			_, finalized, err = c.finalizeStagedSnapshotLocked(context.Background(), nodeID)
			if err != nil {
				deliveries := c.collectResponseDeliveriesLocked()
				c.mutex.Unlock()
				c.deliverResponses(deliveries)
				return nil, err
			}
		}
	}

	watch := c.addTrackedWatchLocked(request, respChan)
	watch.cancel, err = c.SnapshotCache.CreateWatch(request, sub, watch.relay.inner)
	if err != nil {
		watch.closed = true
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

// GetAllResources returns cache-owned immutable state. The returned pointer and
// all of its maps and protobuf values must only be read. Callers making an update
// must copy the Resources and every map they modify before publishing it.
func (c *cacheImpl) GetAllResources(nodeID string) *xds.Resources {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.resourcesInSnapshot[nodeID]
}

func (c *cacheImpl) AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for _, resourceType := range snapshotResourceTypes {
		if left.GetVersion(resourceType) != right.GetVersion(resourceType) {
			return true
		}
	}
	return false
}
