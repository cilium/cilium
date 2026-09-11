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

type Cache interface {
	cache.SnapshotCache

	GetVersion(resources *xds.Resources) string
	GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error)
	// GenerateSnapshotIncrementally reuses immutable state from previous for
	// resource types outside changedTypeURLs. A nil change set requests a full
	// snapshot; a non-nil empty set returns the previous snapshot unchanged.
	GenerateSnapshotIncrementally(resources *xds.Resources, previous cache.ResourceSnapshot, changedTypeURLs map[string]struct{}, logger *slog.Logger) (cache.ResourceSnapshot, error)
	UpdateSnapshot(ctx context.Context, nodeID string, generation uint64, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFunc RevertFunc) error
	// AwaitCurrentVersion registers completions against the current snapshot
	// without publishing it again.
	AwaitCurrentVersion(nodeID string, wg *completion.WaitGroup, typeURLs map[string]func(err error)) error
	// SetResources transfers resources to the cache as immutable published state.
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
	// resourcesInSnapshot holds the last set of resources (keyed by nodeID) pushed to Envoy.
	resourcesInSnapshot map[string]*xds.Resources
	// snapshotGenerations records the generation associated with the current
	// snapshot for each node. AwaitCurrentVersion uses it to attach a no-op
	// update to the response which actually carries that snapshot.
	snapshotGenerations map[string]uint64
	logger              *slog.Logger
	hasher              hash.Hash32
	completionCbs       *callbacks.CompletionCallbacks
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
		snapshotGenerations: make(map[string]uint64),
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

// SetResources stores resources as cache-owned immutable state. It intentionally
// does not clone resources; callers transfer ownership when calling this method.
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

type typeGenerationRegistration struct {
	typeURL string
}

func (c *cacheImpl) completeImmediateCompletions(nodeID string, immediateCompletions []immediateCompletion) {
	for _, completion := range immediateCompletions {
		if completion.completeUnsentCompletions {
			c.completionCbs.CompleteCompletionsThroughGeneration(nodeID, completion.typeURL, completion.generation, nil)
		}
		completion.comp.Complete(completion.err)
	}
}

func (c *cacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, generation uint64, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFunc RevertFunc) error {
	oldSnapshot, _ := c.GetSnapshot(nodeID)
	c.mutex.RLock()
	oldGeneration := c.snapshotGenerations[nodeID]
	c.mutex.RUnlock()
	completions, immediateCompletions := c.registerGenerationCompletions(nodeID, generation, newSnapshot, oldSnapshot, wg, updatedTypeURLS, revertFunc)

	// Stage the authoritative generation before SetSnapshot. go-control-plane
	// can synchronously build a response while SetSnapshot is running, and a
	// concurrent CreateWatch may use context.Background instead of ctx.
	c.completionCbs.SetPublishedSnapshot(nodeID, generation, newSnapshot)
	var registrations []typeGenerationRegistration
	var completeUnsentTypeURLs []string
	for _, typeURL := range snapshotResourceTypes {
		if wg != nil {
			if _, tracked := updatedTypeURLS[typeURL]; tracked {
				// The pending completion carries this generation's revert. Only
				// updates without a completion need a separate generation entry.
				continue
			}
		}
		version := newSnapshot.GetVersion(typeURL)
		versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
		registered, completeUnsent := c.completionCbs.AddTypeGeneration(
			generation, version, typeURL, nodeID, versionChanged, revertFunc)
		if registered {
			registrations = append(registrations, typeGenerationRegistration{typeURL: typeURL})
		}
		if completeUnsent {
			completeUnsentTypeURLs = append(completeUnsentTypeURLs, typeURL)
		}
	}
	if len(newSnapshot.GetResourcesAndTTL(NetworkPolicyTypeURL)) == 0 {
		completeUnsentTypeURLs = append(completeUnsentTypeURLs, NetworkPolicyTypeURL)
	}
	err := c.SetSnapshot(callbacks.WithSnapshotGeneration(ctx, generation), nodeID, newSnapshot)

	if err != nil {
		// SnapshotCache stores the snapshot before delivering watch responses. A
		// canceled delivery may therefore return an error after publication has
		// committed; keep generation state in that case.
		currentSnapshot, getErr := c.GetSnapshot(nodeID)
		committed := getErr == nil && !c.AreDifferentSnapshots(currentSnapshot, newSnapshot)
		if !committed {
			c.completionCbs.SetPublishedSnapshot(nodeID, oldGeneration, oldSnapshot)
			for _, comp := range completions {
				c.completionCbs.RemoveTypeGenerationCompletion(comp)
			}
			for _, registration := range registrations {
				c.completionCbs.RemoveTypeGeneration(nodeID, registration.typeURL, generation)
			}
			return err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}
	c.mutex.Lock()
	c.snapshotGenerations[nodeID] = generation
	c.mutex.Unlock()
	for _, typeURL := range completeUnsentTypeURLs {
		c.completionCbs.CompleteCompletionsThroughGeneration(nodeID, typeURL, generation, nil)
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

	currentSnapshot, err := c.GetSnapshot(nodeID)
	if err != nil {
		return fmt.Errorf("failed to get current snapshot for node %s: %w", nodeID, err)
	}
	if currentSnapshot == nil {
		return fmt.Errorf("missing current snapshot for node %s", nodeID)
	}
	c.mutex.RLock()
	generation := c.snapshotGenerations[nodeID]
	c.mutex.RUnlock()

	_, immediateCompletions := c.registerGenerationCompletions(nodeID, generation, currentSnapshot, currentSnapshot, wg, typeURLs, nil)
	c.completeImmediateCompletions(nodeID, immediateCompletions)
	return nil
}

func (c *cacheImpl) ClearSnapshot(nodeID string) {
	c.SnapshotCache.ClearSnapshot(nodeID)
	c.completionCbs.SetPublishedSnapshot(nodeID, 0, nil)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourcesInSnapshot[nodeID] = &xds.Resources{}
	delete(c.snapshotGenerations, nodeID)
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

func (c *cacheImpl) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	if request != nil && request.GetTypeUrl() == envoy_resource.SecretType && len(request.GetResourceNames()) == 0 {
		c.logger.Debug("Ignoring empty ADS SDS watch")
		return func() {}, nil
	}
	request = normalizeCustomWildcardRequest(request, sub)
	return c.SnapshotCache.CreateWatch(request, sub, respChan)
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
