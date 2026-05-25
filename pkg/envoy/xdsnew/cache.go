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
)

const (
	// NetworkPolicyTypeURL is the type URL of NetworkPolicy resources.
	NetworkPolicyTypeURL      = "type.googleapis.com/cilium.NetworkPolicy"
	NetworkPolicyHostsTypeUrl = "type.googleapis.com/cilium.NetworkPolicyHosts"
	logFieldComponent         = "component"
)

type Cache interface {
	cache.SnapshotCache

	GetVersion(resources *xds.Resources) string
	GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error)
	UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFunc func()) error
	SetResources(nodeID string, resources *xds.Resources)
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
	logger              *slog.Logger
	hasher              hash.Hash32
	completionCbs       *callbacks.CompletionCallbacks
}

var _ Cache = &cacheImpl{}

// ciliumSnapshot implements go-control-plane's ResourceSnapshot interface for
// both Envoy core resources and Cilium-specific xDS resources.
type ciliumSnapshot struct {
	Resources  map[string]cache.Resources
	VersionMap map[string]map[string]string
}

// Ensure ciliumSnapshot implements cache.ResourceSnapshot.
var _ cache.ResourceSnapshot = &ciliumSnapshot{}

var snapshotResourceTypes = []envoy_resource.Type{
	envoy_resource.EndpointType,
	envoy_resource.ClusterType,
	envoy_resource.RouteType,
	envoy_resource.ListenerType,
	envoy_resource.SecretType,
	NetworkPolicyTypeURL,
	NetworkPolicyHostsTypeUrl,
}

func newCiliumSnapshot(resources map[string]cache.Resources) *ciliumSnapshot {
	w := &ciliumSnapshot{
		Resources: make(map[string]cache.Resources, len(snapshotResourceTypes)),
	}
	for _, typeURL := range snapshotResourceTypes {
		w.Resources[typeURL] = resources[typeURL]
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

func NewCache(logger *slog.Logger) Cache {
	snapshotCache := cache.NewSnapshotCache( /*ads*/ true, cache.IDHash{}, snapshotCacheLogger(logger))

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

func (c *cacheImpl) resourceVersion(typeURL string, resources map[string]cache_types.Resource) (string, error) {
	keys := slices.Collect(maps.Keys(resources))
	slices.Sort(keys)
	var sb strings.Builder
	for _, name := range keys {
		encodedResource, err := marshal(resources[name])
		if err != nil {
			return "", err
		}
		sb.WriteString(name)
		sb.WriteString(encodedResource)
	}
	return c.hash(map[string]string{typeURL: sb.String()}), nil
}

func (c *cacheImpl) GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (cache.ResourceSnapshot, error) {
	if resources == nil {
		empty := xds.NewResources()
		resources = &empty
	}

	endpoints := make(map[string]cache_types.Resource, len(resources.Endpoints))
	clusters := make(map[string]cache_types.Resource, len(resources.Clusters))
	routes := make(map[string]cache_types.Resource, len(resources.Routes))
	listeners := make(map[string]cache_types.Resource, len(resources.Listeners))
	networkPolicies := make(map[string]cache_types.Resource, len(resources.NetworkPolicies))
	networkPolicyHosts := make(map[string]cache_types.Resource, len(resources.NetworkPolicyHosts))
	secrets := make(map[string]cache_types.Resource, len(resources.Secrets))

	for name, r := range resources.Endpoints {
		// Skip wildcard :* endpoints that have no matching cluster,
		// as they cause snapshot inconsistency (EDS count > CDS references).
		// These are generated for backward compatibility with the old per-type
		// xDS caches but are not needed in the ADS snapshot.
		if _, hasCluster := resources.Clusters[name]; !hasCluster && len(name) > 2 && name[len(name)-2:] == ":*" {
			continue
		}
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

	resourceGroups := map[string]map[string]cache_types.Resource{
		envoy_resource.EndpointType: endpoints,
		envoy_resource.ClusterType:  clusters,
		envoy_resource.RouteType:    routes,
		envoy_resource.ListenerType: listeners,
		envoy_resource.SecretType:   secrets,
		NetworkPolicyTypeURL:        networkPolicies,
		NetworkPolicyHostsTypeUrl:   networkPolicyHosts,
	}

	versionedResources := make(map[string]cache.Resources, len(resourceGroups))
	for typeURL, resources := range resourceGroups {
		version, err := c.resourceVersion(typeURL, resources)
		if err != nil {
			return nil, err
		}
		versionedResources[typeURL] = resourceGroup(version, resources)
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

func (c *cacheImpl) UpdateSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot, wg *completion.WaitGroup, updatedTypeURLS map[string]func(err error), revertFunc func()) error {
	type immediateCompletion struct {
		comp                      *completion.Completion
		typeURL                   string
		err                       error
		completeUnsentCompletions bool
	}

	completions := make([]*completion.Completion, 0, len(updatedTypeURLS))
	immediateCompletions := make([]immediateCompletion, 0, 1)
	if wg != nil && len(updatedTypeURLS) > 0 {
		oldSnapshot, _ := c.GetSnapshot(nodeID)
		for typeURL, completionCallback := range updatedTypeURLS {
			comp := wg.AddCompletionWithCallback(nil, completionCallback)
			if typeURL == NetworkPolicyTypeURL && len(newSnapshot.GetResources(NetworkPolicyTypeURL)) == 0 {
				immediateCompletions = append(immediateCompletions, immediateCompletion{comp: comp})
				continue
			}
			version := newSnapshot.GetVersion(typeURL)
			versionChanged := oldSnapshot == nil || oldSnapshot.GetVersion(typeURL) != version
			registered, err := c.completionCbs.AddTypeVersionCompletion(comp, version, typeURL, nodeID, versionChanged, revertFunc)
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
	err := c.SetSnapshot(ctx, nodeID, newSnapshot)

	if err != nil {
		for _, comp := range completions {
			c.completionCbs.RemoveTypeVersionCompletion(comp)
		}
		return err
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
	case NetworkPolicyTypeURL, NetworkPolicyHostsTypeUrl:
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

func (c *cacheImpl) AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for _, resourceType := range snapshotResourceTypes {
		if left.GetVersion(resourceType) != right.GetVersion(resourceType) {
			return true
		}
	}
	return false
}
