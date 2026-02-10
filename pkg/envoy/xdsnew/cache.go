package xdsnew

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"log/slog"

	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/davecgh/go-spew/spew"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"k8s.io/apimachinery/pkg/util/rand"
)

type Cache struct {
	// mutex protects accesses to the configuration resources below.
	mutex *lock.RWMutex
	// resourcesInSnapshot holds the last set of resources (keyed by nodeID) pushed to Envoy.
	resourcesInSnapshot map[string]*xds.Resources
	snapshotCache       cache.SnapshotCache
	logger              *slog.Logger
	hasher              hash.Hash32
}

var _ cache.SnapshotCache = Cache{}

func NewCache(logger *slog.Logger) Cache {
	return Cache{
		snapshotCache: cache.NewSnapshotCache( /*ads*/ true, cache.IDHash{} /*logger*/, nil),
		logger:        logger,
		hasher:        fnv.New32a(),
	}
}

func (c *Cache) hash(resources map[string]string) string {
	c.hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	printer.Fprintf(c.hasher, "%#v", resources)
	return rand.SafeEncodeString(fmt.Sprint(c.hasher.Sum32()))
}

func (c *Cache) GetVersion(resources *xds.Resources) string {
	encodedResources, err := Marshal(resources)
	if err != nil {
		c.logger.Error(fmt.Sprintf("failed to marshal resources for versioning: %v", err))
		return ""
	}
	return c.hash(encodedResources)
}

func (c *Cache) GenerateSnapshot(resources *xds.Resources, logger *slog.Logger) (*cache.Snapshot, error) {
	endpoints := make([]cache_types.Resource, 0, len(resources.Endpoints))
	clusters := make([]cache_types.Resource, 0, len(resources.Clusters))
	routes := make([]cache_types.Resource, 0, len(resources.Routes))
	listeners := make([]cache_types.Resource, 0, len(resources.Listeners))
	extensionConfigs := make([]cache_types.Resource, 0, len(resources.NetworkPolicies))
	secrets := make([]cache_types.Resource, 0, len(resources.Secrets))

	for _, r := range resources.Endpoints {
		endpoints = append(endpoints, r)
	}
	for _, r := range resources.Clusters {
		clusters = append(clusters, r)
	}
	for _, r := range resources.Routes {
		routes = append(routes, r)
	}
	for _, r := range resources.Listeners {
		listeners = append(listeners, r)
	}
	for _, r := range resources.Secrets {
		secrets = append(secrets, r)
	}
	for _, r := range resources.NetworkPolicies {
		extensionConfigs = append(extensionConfigs, r)
	}

	version := c.GetVersion(resources)

	// todo nezdolik figure out versioning
	snapshot, err := cache.NewSnapshot(version, map[envoy_resource.Type][]cache_types.Resource{
		envoy_resource.EndpointType:        endpoints,
		envoy_resource.ClusterType:         clusters,
		envoy_resource.RouteType:           routes,
		envoy_resource.ListenerType:        listeners,
		envoy_resource.SecretType:          secrets,
		envoy_resource.ExtensionConfigType: extensionConfigs,
	})
	if err != nil {
		c.logger.Error("failed to generate snapshot: %q", logfields.Error, err)
		return nil, err
	}
	if err = snapshot.Consistent(); err != nil {
		c.logger.Error(fmt.Sprintf("failed due to snapshot inconsistency: %q", err))
		return nil, err
	}
	return snapshot, nil
}

func (c Cache) GetSnapshot(nodeID string) (cache.ResourceSnapshot, error) {
	snap, err := c.snapshotCache.GetSnapshot(nodeID)
	if err != nil {
		return &cache.Snapshot{}, err
	}

	return snap, nil
}

func (c Cache) SetResources(nodeID string, resources *xds.Resources) {
	c.resourcesInSnapshot[nodeID] = resources
}

func (c Cache) SetSnapshot(ctx context.Context, nodeID string, newSnapshot cache.ResourceSnapshot) error {
	return c.snapshotCache.SetSnapshot(ctx, nodeID, newSnapshot)
}

func (c Cache) ClearSnapshot(nodeID string) {
	c.snapshotCache.ClearSnapshot(nodeID)
	c.resourcesInSnapshot[nodeID] = &xds.Resources{}
}

func (c Cache) ClearSnapshotForType(nodeID string, resourceType envoy_resource.Type) {
	resources, exists := c.resourcesInSnapshot[nodeID]
	if !exists {
		c.logger.Warn(fmt.Sprintf("No resources found for node %s when clearing snapshot for resource type %s", nodeID, resourceType))
		return
	}
	switch resourceType {
	case envoy_resource.EndpointType:
		resources.Endpoints = map[string]*envoy_config_endpoint.ClusterLoadAssignment{}
	case envoy_resource.ClusterType:
		resources.Clusters = map[string]*envoy_config_cluster.Cluster{}
	case envoy_resource.RouteType:
		resources.Routes = map[string]*envoy_config_route.RouteConfiguration{}
	case envoy_resource.ListenerType:
		resources.Listeners = map[string]*envoy_config_listener.Listener{}
	case envoy_resource.SecretType:
		resources.Secrets = map[string]*envoy_config_tls.Secret{}
	case envoy_resource.ExtensionConfigType:
		resources.NetworkPolicies = map[string]*cilium.NetworkPolicy{}
	default:
		c.logger.Warn(fmt.Sprintf("Clearing snapshot for resource type %s is not supported", resourceType))
	}
	newSnapshot, err := c.GenerateSnapshot(resources, c.logger)
	if err != nil {
		c.logger.Error(fmt.Sprintf("Failed to generate snapshot after clearing resources of type %s for node %s: %v", resourceType, nodeID, err))
		return
	}
	if err = c.SetSnapshot(context.Background(), nodeID, newSnapshot); err != nil {
		c.logger.Error(fmt.Sprintf("Failed to set snapshot after clearing resources of type %s for node %s: %v", resourceType, nodeID, err))
		return
	}
}

func (c Cache) CreateDeltaWatch(*cache.DeltaRequest, cache.Subscription, chan cache.DeltaResponse) (cancel func(), err error) {
	panic("unimplemented")
}

func (c Cache) CreateWatch(request *cache.Request, sub cache.Subscription, respChan chan cache.Response) (cancel func(), err error) {
	return c.snapshotCache.CreateWatch(request, sub, respChan)
}

// Fetch implements cache.SnapshotCache.
func (c Cache) Fetch(context context.Context, request *cache.Request) (cache.Response, error) {
	return c.snapshotCache.Fetch(context, request)
}

// GetStatusInfo implements cache.SnapshotCache.
func (c Cache) GetStatusInfo(node string) cache.StatusInfo {
	return c.snapshotCache.GetStatusInfo(node)
}

func (c Cache) GetAllResources(nodeID string) *xds.Resources {
	return c.resourcesInSnapshot[nodeID]
}

// GetStatusKeys implements cache.SnapshotCache.
func (c Cache) GetStatusKeys() []string {
	return c.snapshotCache.GetStatusKeys()
}

func (c Cache) AreDifferentSnapshots(left, right cache.ResourceSnapshot) bool {
	for _, resourceType := range []envoy_resource.Type{
		envoy_resource.EndpointType, envoy_resource.ClusterType, envoy_resource.RouteType,
		envoy_resource.ListenerType, envoy_resource.SecretType, /*, envoy.ExtensionConfig */
	} {
		if left.GetVersion(resourceType) != right.GetVersion(resourceType) {
			return true
		}
	}
	return false
}
