// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"iter"
	"log/slog"
	"maps"
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

	GetVersion(resources *xds.Resources) string
	GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error)
	UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFuncs map[string]func()) error
	SetResources(nodeID string, resources *xds.Resources)
	GetAllResources(nodeID string) *xds.Resources
	// GetResource returns one immutable resource without exposing the containing map.
	GetResource(nodeID string, typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool)
	// Resource iterators expose immutable protobufs without copying or exposing
	// the containing maps. Iteration holds the cache read lock, so loop bodies
	// must not call back into the cache.
	Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener]
	Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration]
	NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy]
	AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool
	GetCompletionCallbacks() *callbacks.CompletionCallbacks
}

type cacheImpl struct {
	cache.SnapshotCache

	// mutex protects accesses to the configuration resources below.
	mutex *lock.RWMutex
	// resourcesInSnapshot holds the last set of resources (keyed by nodeID) pushed to Envoy.
	resourcesInSnapshot map[string]*xds.Resources
	logger              *slog.Logger
	hasher              hash.Hash32
	completionCbs       *callbacks.CompletionCallbacks
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

var snapshotResourceTypes = []envoy_resource.Type{
	envoy_resource.EndpointType,
	envoy_resource.ClusterType,
	envoy_resource.RouteType,
	envoy_resource.ListenerType,
	envoy_resource.SecretType,
	NetworkPolicyTypeURL,
	NetworkPolicyHostsTypeURL,
}

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

func NewCache(logger *slog.Logger, strictAdsMode bool) Cache {
	snapshotCache := cache.NewSnapshotCache(strictAdsMode, cache.IDHash{}, snapshotCacheLogger(logger))

	return &cacheImpl{
		SnapshotCache:       snapshotCache,
		mutex:               &lock.RWMutex{},
		resourcesInSnapshot: make(map[string]*xds.Resources),
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

func (c *cacheImpl) resourceGroup(typeURL typeurl.Index, resources map[string]cache_types.Resource, versionContext string) (cache.Resources, map[string]string, error) {
	items := make(map[string]cache_types.ResourceWithTTL, len(resources))
	versions := make(map[string]string, len(resources))
	for name, resource := range resources {
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
	return cache.Resources{
		Version: c.resourceVersion(typeURL, versions, versionContext),
		Items:   items,
	}, versions, nil
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
	endpoints := make(map[string]cache_types.Resource, len(resources.Endpoints))
	clusters := make(map[string]cache_types.Resource, len(resources.Clusters))
	routes := make(map[string]cache_types.Resource, len(resources.Routes))
	listeners := make(map[string]cache_types.Resource, len(resources.Listeners))
	networkPolicies := make(map[string]cache_types.Resource, len(resources.NetworkPolicies))
	networkPolicyHosts := make(map[string]cache_types.Resource, len(resources.NetworkPolicyHosts))
	secrets := make(map[string]cache_types.Resource, len(resources.Secrets))

	for name, r := range resources.Endpoints {
		endpoints[name] = r
	}
	for name, r := range resources.Clusters {
		clusters[name] = r
	}
	for name, r := range resources.Routes {
		routes[name] = r
	}
	for name, r := range resources.Listeners {
		listeners[name] = r
	}
	for name, r := range resources.NetworkPolicies {
		networkPolicies[name] = r
	}
	for name, r := range resources.NetworkPolicyHosts {
		networkPolicyHosts[name] = r
	}
	for name, r := range resources.Secrets {
		secrets[name] = r
	}

	resourceGroups := typeurl.Slots[map[string]cache_types.Resource]{
		typeurl.Endpoint:           endpoints,
		typeurl.Cluster:            clusters,
		typeurl.Route:              routes,
		typeurl.Listener:           listeners,
		typeurl.Secret:             secrets,
		typeurl.NetworkPolicy:      networkPolicies,
		typeurl.NetworkPolicyHosts: networkPolicyHosts,
	}

	var versionedResources typeurl.Slots[snapshotResourceGroup]
	for typeURL := range typeurl.Indices() {
		resourceMap := resourceGroups[typeURL]
		var versionContext string
		if typeURL == typeurl.Endpoint {
			// Envoy creates one EDS subscription per EDS-backed cluster. A new
			// parent can request a dependent resource that the ADS stream has already
			// seen at the current version, so go-control-plane may open the new watch
			// without replaying the cached resource. Include the parent reference sets
			// in dependent resource versions so new subscriptions receive the current
			// resource immediately.
			versionContext = edsClusterReferenceVersionContext(resources)
		} else if typeURL == typeurl.Route {
			versionContext = rdsListenerReferenceVersionContext(resources)
		} else if typeURL == typeurl.Secret {
			versionContext = sdsReferenceVersionContext(resources)
		} else if typeURL == typeurl.Cluster {
			versionContext = listenerClusterReferenceVersionContext(resources)
		}
		group, versions, err := c.resourceGroup(typeURL, resourceMap, versionContext)
		if err != nil {
			return nil, err
		}
		versionedResources[typeURL] = snapshotResourceGroup{
			resources: group,
			versions:  versions,
		}
	}

	return newCiliumSnapshot(versionedResources), nil
}

func (c *cacheImpl) GetCompletionCallbacks() *callbacks.CompletionCallbacks {
	return c.completionCbs
}

func (c *cacheImpl) SetResources(nodeID string, resources *xds.Resources) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourcesInSnapshot[nodeID] = resources
}

func (c *cacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFuncs map[string]func()) error {
	type immediateCompletion struct {
		comp                      *completion.Completion
		typeURL                   string
		err                       error
		completeUnsentCompletions bool
	}

	completions := make([]*completion.Completion, 0, len(updatedTypeURLS))
	immediateCompletions := make([]immediateCompletion, 0, 1)
	handledTypeURLs := make(map[string]struct{}, len(updatedTypeURLS))
	oldSnapshot, _ := c.GetSnapshot(nodeID)
	if wg != nil && len(updatedTypeURLS) > 0 {
		for typeURL, completionCallback := range updatedTypeURLS {
			handledTypeURLs[typeURL] = struct{}{}
			version := newSnapshot.GetVersion(typeURL)
			owner := c.completionCbs.NewTypeVersionCompletionOwner(nodeID, typeURL, version)
			comp := wg.AddCompletionWithCallback(owner, completionCallback)
			if typeURL == NetworkPolicyTypeURL && len(newSnapshot.GetResources(NetworkPolicyTypeURL)) == 0 {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					completeUnsentCompletions: true,
				})
				continue
			}
			versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
			registered, err := c.completionCbs.AddTypeVersionCompletion(comp, version, typeURL, nodeID, versionChanged, revertFuncs[typeURL])
			if !registered {
				immediateCompletions = append(immediateCompletions, immediateCompletion{
					comp:                      comp,
					typeURL:                   typeURL,
					err:                       err,
					completeUnsentCompletions: err == nil,
				})
				continue
			}
			completions = append(completions, comp)
		}
	}

	// A newer snapshot may be published without a completion, for example when
	// the synthetic ingress endpoint updates NPDS. Record changed versions while
	// older completions are pending so a response for the newer snapshot can
	// claim and eventually complete coalesced updates.
	markers := make([]*callbacks.TypeVersionMarker, 0, len(snapshotResourceTypes))
	completeUnsentTypeURLs := make([]string, 0, 1)
	for _, typeURL := range snapshotResourceTypes {
		if _, handled := handledTypeURLs[typeURL]; handled {
			continue
		}
		// An empty NPDS snapshot intentionally does not wait for an ACK.
		if typeURL == NetworkPolicyTypeURL && len(newSnapshot.GetResources(typeURL)) == 0 {
			completeUnsentTypeURLs = append(completeUnsentTypeURLs, typeURL)
			continue
		}
		version := newSnapshot.GetVersion(typeURL)
		versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
		marker, completeUnsent := c.completionCbs.AddTypeVersionMarker(version, typeURL, nodeID, versionChanged, revertFuncs[typeURL])
		if marker != nil {
			markers = append(markers, marker)
		}
		if completeUnsent {
			completeUnsentTypeURLs = append(completeUnsentTypeURLs, typeURL)
		}
	}
	err := c.SetSnapshot(ctx, nodeID, newSnapshot)

	if err != nil {
		// go-control-plane stores a snapshot before delivering responses and can
		// return an error after the new snapshot is already observable. Treat that
		// case as committed so callback ordering and resourcesInSnapshot stay in
		// sync with the underlying cache.
		currentSnapshot, getErr := c.GetSnapshot(nodeID)
		committed := getErr == nil && !c.AreDifferentSnapshots(currentSnapshot, newSnapshot)
		if !committed {
			for _, comp := range completions {
				c.completionCbs.RemoveTypeVersionCompletion(comp)
			}
			for _, marker := range markers {
				c.completionCbs.RemoveTypeVersionMarker(marker)
			}
			return err
		}
		c.logger.Debug("Snapshot was installed despite response delivery error",
			logfields.NodeID, nodeID,
			logfields.Error, err)
	}
	for _, typeURL := range completeUnsentTypeURLs {
		c.completionCbs.CompleteUnsentPendingCompletions(nodeID, typeURL, nil)
	}
	for _, completion := range immediateCompletions {
		if completion.completeUnsentCompletions {
			c.completionCbs.CompleteUnsentPendingCompletions(nodeID, completion.typeURL, nil)
		}
		completion.comp.Complete(completion.err)
	}

	return nil
}

func (c *cacheImpl) ClearSnapshot(nodeID string) {
	c.SnapshotCache.ClearSnapshot(nodeID)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resourcesInSnapshot[nodeID] = &xds.Resources{}
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

func (c *cacheImpl) GetAllResources(nodeID string) *xds.Resources {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.resourcesInSnapshot[nodeID]
}

func (c *cacheImpl) GetResource(nodeID string, typeURL typeurl.Index, resourceName string) (cache_types.Resource, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	resources := c.resourcesInSnapshot[nodeID]
	if resources == nil {
		return nil, false
	}
	switch typeURL {
	case typeurl.Endpoint:
		if resource := resources.Endpoints[resourceName]; resource != nil {
			return resource, true
		}
	case typeurl.Cluster:
		if resource := resources.Clusters[resourceName]; resource != nil {
			return resource, true
		}
	case typeurl.Route:
		if resource := resources.Routes[resourceName]; resource != nil {
			return resource, true
		}
	case typeurl.Listener:
		if resource := resources.Listeners[resourceName]; resource != nil {
			return resource, true
		}
	case typeurl.Secret:
		if resource := resources.Secrets[resourceName]; resource != nil {
			return resource, true
		}
	case typeurl.NetworkPolicy:
		if resource := resources.NetworkPolicies[resourceName]; resource != nil {
			return resource, true
		}
	case typeurl.NetworkPolicyHosts:
		if resource := resources.NetworkPolicyHosts[resourceName]; resource != nil {
			return resource, true
		}
	}
	return nil, false
}

func (c *cacheImpl) Listeners(nodeID string) iter.Seq2[string, *envoy_config_listener.Listener] {
	return func(yield func(string, *envoy_config_listener.Listener) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		if resources := c.resourcesInSnapshot[nodeID]; resources != nil {
			for name, resource := range resources.Listeners {
				if resource != nil && !yield(name, resource) {
					return
				}
			}
		}
	}
}

func (c *cacheImpl) Routes(nodeID string) iter.Seq2[string, *envoy_config_route.RouteConfiguration] {
	return func(yield func(string, *envoy_config_route.RouteConfiguration) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		if resources := c.resourcesInSnapshot[nodeID]; resources != nil {
			for name, resource := range resources.Routes {
				if resource != nil && !yield(name, resource) {
					return
				}
			}
		}
	}
}

func (c *cacheImpl) NetworkPolicies(nodeID string) iter.Seq2[string, *cilium.NetworkPolicy] {
	return func(yield func(string, *cilium.NetworkPolicy) bool) {
		c.mutex.RLock()
		defer c.mutex.RUnlock()
		if resources := c.resourcesInSnapshot[nodeID]; resources != nil {
			for name, resource := range resources.NetworkPolicies {
				if resource != nil && !yield(name, resource) {
					return
				}
			}
		}
	}
}

func (c *cacheImpl) AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for _, resourceType := range snapshotResourceTypes {
		if left.GetVersion(resourceType) != right.GetVersion(resourceType) {
			return true
		}
	}
	return false
}
