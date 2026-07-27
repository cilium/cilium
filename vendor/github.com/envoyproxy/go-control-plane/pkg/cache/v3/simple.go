// Copyright 2018 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package cache

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/log"
)

// ResourceSnapshot is an abstract snapshot of a collection of resources that
// can be stored in a SnapshotCache. This enables applications to use the
// SnapshotCache watch machinery with their own resource types. Most
// applications will use Snapshot.
type ResourceSnapshot interface {
	// GetVersion should return the current version of the resource indicated
	// by typeURL. The version string that is returned is opaque and should
	// only be compared for equality.
	GetVersion(typeURL string) string

	// GetResourcesAndTTL returns all resources of the type indicted by
	// typeURL, together with their TTL.
	GetResourcesAndTTL(typeURL string) map[string]types.ResourceWithTTL

	// GetResources returns all resources of the type indicted by
	// typeURL. This is identical to GetResourcesAndTTL, except that
	// the TTL is omitted.
	GetResources(typeURL string) map[string]types.Resource

	// ConstructVersionMap is a hint that a delta watch will soon make a
	// call to GetVersionMap. The snapshot should construct an internal
	// opaque version string for each collection of resource types.
	ConstructVersionMap() error

	// GetVersionMap returns a map of resource name to resource version for
	// all the resources of type indicated by typeURL.
	GetVersionMap(typeURL string) map[string]string
}

// SnapshotCache is a snapshot-based cache that maintains a single versioned
// snapshot of responses per node. SnapshotCache consistently replies with the
// latest snapshot. For the protocol to work correctly in ADS mode, EDS/RDS
// requests are responded only when all resources in the snapshot xDS response
// are named as part of the request. It is expected that the CDS response names
// all EDS clusters, and the LDS response names all RDS routes in a snapshot,
// to ensure that Envoy makes the request for all EDS clusters or RDS routes
// eventually.
//
// SnapshotCache can operate as a REST or regular xDS backend. The snapshot
// can be partial, e.g. only include RDS or EDS resources.
type SnapshotCache interface {
	Cache

	// SetSnapshot sets a response snapshot for a node. For ADS, the snapshots
	// should have distinct versions and be internally consistent (e.g. all
	// referenced resources must be included in the snapshot).
	//
	// This method will cause the server to respond to all open watches, for which
	// the version differs from the snapshot version.
	SetSnapshot(ctx context.Context, node string, snapshot ResourceSnapshot) error

	// GetSnapshots gets the snapshot for a node.
	GetSnapshot(node string) (ResourceSnapshot, error)

	// ClearSnapshot removes all status and snapshot information associated with a node.
	ClearSnapshot(node string)

	// GetStatusInfo retrieves status information for a node ID.
	GetStatusInfo(string) StatusInfo

	// GetStatusKeys retrieves node IDs for all statuses.
	GetStatusKeys() []string
}

type snapshotCache struct {
	// watchCount and deltaWatchCount are atomic counters incremented for each watch respectively. They need to
	// be the first fields in the struct to guarantee 64-bit alignment,
	// which is a requirement for atomic operations on 64-bit operands to work on
	// 32-bit machines.
	watchCount      int64
	deltaWatchCount int64

	log log.Logger

	// ads flag to hold responses until all resources are named
	ads bool

	// snapshots are cached resources indexed by node IDs
	snapshots map[string]ResourceSnapshot

	// status information for all nodes indexed by node IDs
	status map[string]*statusInfo

	// hash is the hashing function for Envoy nodes
	hash NodeHash

	mu sync.RWMutex
}

// NewSnapshotCache initializes a simple cache.
//
// ADS flag forces a delay in responding to streaming requests until all
// resources are explicitly named in the request. This avoids the problem of a
// partial request over a single stream for a subset of resources which would
// require generating a fresh version for acknowledgement. ADS flag requires
// snapshot consistency. For non-ADS case (and fetch), multiple partial
// requests are sent across multiple streams and re-using the snapshot version
// is OK.
//
// Logger is optional.
func NewSnapshotCache(ads bool, hash NodeHash, logger log.Logger) SnapshotCache {
	return newSnapshotCache(ads, hash, logger)
}

func newSnapshotCache(ads bool, hash NodeHash, logger log.Logger) *snapshotCache {
	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	cache := &snapshotCache{
		log:       logger,
		ads:       ads,
		snapshots: make(map[string]ResourceSnapshot),
		status:    make(map[string]*statusInfo),
		hash:      hash,
	}

	return cache
}

// NewSnapshotCacheWithHeartbeating initializes a simple cache that sends periodic heartbeat
// responses for resources with a TTL.
//
// ADS flag forces a delay in responding to streaming requests until all
// resources are explicitly named in the request. This avoids the problem of a
// partial request over a single stream for a subset of resources which would
// require generating a fresh version for acknowledgement. ADS flag requires
// snapshot consistency. For non-ADS case (and fetch), multiple partial
// requests are sent across multiple streams and re-using the snapshot version
// is OK.
//
// Logger is optional.
//
// The context provides a way to cancel the heartbeating routine, while the heartbeatInterval
// parameter controls how often heartbeating occurs.
func NewSnapshotCacheWithHeartbeating(ctx context.Context, ads bool, hash NodeHash, logger log.Logger, heartbeatInterval time.Duration) SnapshotCache {
	cache := newSnapshotCache(ads, hash, logger)
	go func() {
		t := time.NewTicker(heartbeatInterval)

		for {
			select {
			case <-t.C:
				cache.mu.Lock()
				for node := range cache.status {
					// TODO(snowp): Omit heartbeats if a real response has been sent recently.
					cache.sendHeartbeats(ctx, node)
				}
				cache.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
	return cache
}

func (cache *snapshotCache) sendHeartbeats(ctx context.Context, node string) {
	snapshot, ok := cache.snapshots[node]
	if !ok {
		return
	}

	if info, ok := cache.status[node]; ok {
		info.mu.Lock()
		for id, watch := range info.watches {
			// Respond with the current version regardless of whether the version has changed.
			version := snapshot.GetVersion(watch.Request.GetTypeUrl())
			resources := snapshot.GetResourcesAndTTL(watch.Request.GetTypeUrl())

			// TODO(snowp): Construct this once per type instead of once per watch.
			resourcesWithTTL := map[string]types.ResourceWithTTL{}
			for k, v := range resources {
				if v.TTL != nil {
					resourcesWithTTL[k] = v
				}
			}

			if len(resourcesWithTTL) == 0 {
				continue
			}
			cache.log.Debugf("respond open watch %d %v with heartbeat for version %q", id, watch.Request.GetResourceNames(), version)
			err := cache.respond(ctx, watch, resourcesWithTTL, version, true)
			if err != nil {
				cache.log.Errorf("received error when attempting to respond to watches: %v", err)
			}

			// The watch must be deleted and we must rely on the client to ack this response to create a new watch.
			delete(info.watches, id)
		}
		info.mu.Unlock()
	}
}

// SetSnapshotCache updates a snapshot for a node.
func (cache *snapshotCache) SetSnapshot(ctx context.Context, node string, snapshot ResourceSnapshot) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.log.Debugf("setting snapshot for node %s", node)
	// update the existing entry
	cache.snapshots[node] = snapshot

	// trigger existing watches for which version changed
	if info, ok := cache.status[node]; ok {
		info.mu.Lock()
		defer info.mu.Unlock()

		// Respond to SOTW watches for the node.
		if err := cache.respondSOTWWatches(ctx, info, snapshot); err != nil {
			return err
		}

		// Respond to delta watches for the node.
		return cache.respondDeltaWatches(ctx, info, snapshot)
	}

	return nil
}

func (cache *snapshotCache) respondSOTWWatches(ctx context.Context, info *statusInfo, snapshot ResourceSnapshot) error {
	// responder callback for SOTW watches
	respond := func(watch ResponseWatch, id int64) error {
		version := snapshot.GetVersion(watch.Request.GetTypeUrl())
		if version != watch.Request.GetVersionInfo() {
			cache.log.Debugf("respond open watch %d %s %v with new version %q", id, watch.Request.GetTypeUrl(), watch.Request.GetResourceNames(), version)
			resources := snapshot.GetResourcesAndTTL(watch.Request.GetTypeUrl())
			err := cache.respond(ctx, watch, resources, version, false)
			if err != nil {
				return err
			}
			// discard the watch
			delete(info.watches, id)
		}
		return nil
	}

	// If ADS is enabled we need to order response watches so we guarantee
	// sending them in the correct order. Go's default implementation
	// of maps are randomized order when ranged over.
	if cache.ads {
		info.orderResponseWatches()
		for _, key := range info.orderedWatches {
			err := respond(info.watches[key.ID], key.ID)
			if err != nil {
				return err
			}
		}
	} else {
		for id, watch := range info.watches {
			err := respond(watch, id)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (cache *snapshotCache) respondDeltaWatches(ctx context.Context, info *statusInfo, snapshot ResourceSnapshot) error {
	// We only calculate version hashes when using delta. We don't
	// want to do this when using SOTW so we can avoid unnecessary
	// computational cost if not using delta.
	if len(info.deltaWatches) == 0 {
		return nil
	}

	err := snapshot.ConstructVersionMap()
	if err != nil {
		return err
	}

	// If ADS is enabled we need to order response delta watches so we guarantee
	// sending them in the correct order. Go's default implementation
	// of maps are randomized order when ranged over.
	if cache.ads {
		info.orderResponseDeltaWatches()
		for _, key := range info.orderedDeltaWatches {
			watch := info.deltaWatches[key.ID]
			res, err := cache.respondDelta(
				ctx,
				snapshot,
				watch.Request,
				watch.Response,
				watch.subscription,
			)
			if err != nil {
				return err
			}
			// If we detect a nil response here, that means there has been no state change
			// so we don't want to respond or remove any existing resource watches
			if res != nil {
				delete(info.deltaWatches, key.ID)
			}
		}
	} else {
		for id, watch := range info.deltaWatches {
			res, err := cache.respondDelta(
				ctx,
				snapshot,
				watch.Request,
				watch.Response,
				watch.subscription,
			)
			if err != nil {
				return err
			}
			// If we detect a nil response here, that means there has been no state change
			// so we don't want to respond or remove any existing resource watches
			if res != nil {
				delete(info.deltaWatches, id)
			}
		}
	}
	return nil
}

// GetSnapshot gets the snapshot for a node, and returns an error if not found.
func (cache *snapshotCache) GetSnapshot(node string) (ResourceSnapshot, error) {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	snap, ok := cache.snapshots[node]
	if !ok {
		return nil, fmt.Errorf("no snapshot found for node %s", node)
	}
	return snap, nil
}

// ClearSnapshot clears snapshot and info for a node.
func (cache *snapshotCache) ClearSnapshot(node string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	delete(cache.snapshots, node)
	delete(cache.status, node)
}

// nameSet creates a map from a string slice to value true.
func nameSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// superset checks that all resources are listed in the names set.
func superset(names map[string]bool, resources map[string]types.ResourceWithTTL) error {
	for resourceName := range resources {
		if _, exists := names[resourceName]; !exists {
			return fmt.Errorf("%q not listed", resourceName)
		}
	}
	return nil
}

// CreateWatch returns a watch for an xDS request.  A nil function may be
// returned if an error occurs.
func (cache *snapshotCache) CreateWatch(request *Request, sub Subscription, value chan Response) (func(), error) {
	nodeID := cache.hash.ID(request.GetNode())

	cache.mu.Lock()
	defer cache.mu.Unlock()

	info, ok := cache.status[nodeID]
	if !ok {
		info = newStatusInfo(request.GetNode())
		cache.status[nodeID] = info
	}

	// update last watch request time
	info.mu.Lock()
	info.lastWatchRequestTime = time.Now()
	info.mu.Unlock()

	createWatch := func(watch ResponseWatch) func() {
		watchID := cache.nextWatchID()
		cache.log.Debugf("open watch %d for %s %v from nodeID %q, version %q", watchID, request.GetTypeUrl(), sub.SubscribedResources(), nodeID, request.GetVersionInfo())
		info.mu.Lock()
		info.watches[watchID] = watch
		info.mu.Unlock()
		return cache.cancelWatch(nodeID, watchID)
	}

	watch := ResponseWatch{Request: request, Response: value, subscription: sub, fullStateResponses: ResourceRequiresFullStateInSotw(request.GetTypeUrl())}

	snapshot, exists := cache.snapshots[nodeID]
	if !exists {
		return createWatch(watch), nil
	}

	version := snapshot.GetVersion(request.GetTypeUrl())
	resources := snapshot.GetResourcesAndTTL(request.GetTypeUrl())

	if request.GetVersionInfo() == version {
		// Retrieve whether there are resources in the cache requested and currently unknown to the client.
		knownResourceNames := sub.ReturnedResources()
		shouldRespond := false
		if !sub.IsWildcard() {
			// Check if there is a subscribed resource available and not yet returned,
			// for instance if it is newly subscribed.
			for r := range sub.SubscribedResources() {
				if _, ok := knownResourceNames[r]; !ok {
					if _, ok := resources[r]; ok {
						shouldRespond = true
						break
					}
				}
			}
		} else {
			// Check if a resource present in the snapshot is currently not returned,
			// for instance if the subscription is newly wildcard.
			for r := range snapshot.GetResources(request.GetTypeUrl()) {
				if _, ok := knownResourceNames[r]; !ok {
					shouldRespond = true
					break
				}
			}
		}
		// The version has not changed, and the client already has all existing requested resources.
		if !shouldRespond {
			return createWatch(watch), nil
		}
	}

	// The version is different, or the client is subscribed to resources not yet returned to it.
	if err := cache.respond(context.Background(), watch, resources, version, false); err != nil {
		cache.log.Errorf("failed to send a response for %s%v to nodeID %q: %s", request.GetTypeUrl(),
			sub.SubscribedResources(), nodeID, err)
		return nil, fmt.Errorf("failed to send the response: %w", err)
	}

	return func() {}, nil
}

func (cache *snapshotCache) nextWatchID() int64 {
	return atomic.AddInt64(&cache.watchCount, 1)
}

// cancellation function for cleaning stale watches
func (cache *snapshotCache) cancelWatch(nodeID string, watchID int64) func() {
	return func() {
		// uses the cache mutex
		cache.mu.RLock()
		defer cache.mu.RUnlock()
		if info, ok := cache.status[nodeID]; ok {
			info.mu.Lock()
			delete(info.watches, watchID)
			info.mu.Unlock()
		}
	}
}

// Respond to a watch with the snapshot value. The value channel should have capacity not to block.
// TODO(kuat) do not respond always, see issue https://github.com/envoyproxy/go-control-plane/issues/46
func (cache *snapshotCache) respond(ctx context.Context, watch ResponseWatch, resources map[string]types.ResourceWithTTL, version string, heartbeat bool) error {
	request := watch.Request
	// for ADS, the request names must match the snapshot names
	// if they do not, then the watch is never responded, and it is expected that envoy makes another request
	if len(request.GetResourceNames()) != 0 && cache.ads {
		if err := superset(nameSet(request.GetResourceNames()), resources); err != nil {
			cache.log.Warnf("ADS mode: not responding to request %s %v: %v", request.GetTypeUrl(), request.GetResourceNames(), err)
			return nil
		}
	}

	resp := createResponse(ctx, request, resources, version, heartbeat)
	cache.log.Debugf("respond %s (requested %v) version %q with version %q and resources %v", request.GetTypeUrl(), request.GetResourceNames(), request.GetVersionInfo(), version, slices.Collect(maps.Keys(resp.GetReturnedResources())))

	select {
	case watch.Response <- resp:
		return nil
	case <-ctx.Done():
		return context.Canceled
	}
}

func createResponse(ctx context.Context, request *Request, resources map[string]types.ResourceWithTTL, version string, heartbeat bool) Response {
	filtered := make([]*cachedResource, 0, len(resources))
	returnedResources := make(map[string]string, len(resources))

	// Reply only with the requested resources. Envoy may ask each resource
	// individually in a separate stream. It is ok to reply with the same version
	// on separate streams since requests do not share their response versions.
	if len(request.GetResourceNames()) != 0 {
		set := nameSet(request.GetResourceNames())
		for name, resource := range resources {
			if set[name] {
				filtered = append(filtered, newCachedResourceWithTTL(name, resource, version))
				returnedResources[name] = version
			}
		}
	} else {
		for name, resource := range resources {
			filtered = append(filtered, newCachedResourceWithTTL(name, resource, version))
			returnedResources[name] = version
		}
	}

	return &RawResponse{
		Request:           request,
		Version:           version,
		resources:         filtered,
		returnedResources: returnedResources,
		Heartbeat:         heartbeat,
		Ctx:               ctx,
	}
}

// CreateDeltaWatch returns a watch for a delta xDS request which implements the Simple SnapshotCache.
func (cache *snapshotCache) CreateDeltaWatch(request *DeltaRequest, sub Subscription, value chan DeltaResponse) (func(), error) {
	nodeID := cache.hash.ID(request.GetNode())
	t := request.GetTypeUrl()

	cache.mu.Lock()
	defer cache.mu.Unlock()

	info, ok := cache.status[nodeID]
	if !ok {
		info = newStatusInfo(request.GetNode())
		cache.status[nodeID] = info
	}

	// update last watch request time
	info.setLastDeltaWatchRequestTime(time.Now())

	// find the current cache snapshot for the provided node
	snapshot, exists := cache.snapshots[nodeID]

	// There are three different cases that leads to a delayed watch trigger:
	// - no snapshot exists for the requested nodeID
	// - a snapshot exists, but we failed to initialize its version map
	// - we attempted to issue a response, but the caller is already up to date
	delayedResponse := !exists
	if exists {
		err := snapshot.ConstructVersionMap()
		if err != nil {
			cache.log.Errorf("failed to compute version for snapshot resources inline: %s", err)
		}
		response, err := cache.respondDelta(context.Background(), snapshot, request, value, sub)
		if err != nil {
			cache.log.Errorf("failed to respond with delta response: %s", err)
		}

		delayedResponse = response == nil
	}

	if delayedResponse {
		watchID := cache.nextDeltaWatchID()

		if exists {
			cache.log.Infof("open delta watch ID:%d for %s Resources:%v from nodeID: %q,  version %q", watchID, t, sub.SubscribedResources(), nodeID, snapshot.GetVersion(t))
		} else {
			cache.log.Infof("open delta watch ID:%d for %s Resources:%v from nodeID: %q", watchID, t, sub.SubscribedResources(), nodeID)
		}

		info.setDeltaResponseWatch(watchID, DeltaResponseWatch{Request: request, Response: value, subscription: sub})
		return cache.cancelDeltaWatch(nodeID, watchID), nil
	}

	return nil, nil
}

// Respond to a delta watch with the provided snapshot value. If the response is nil, there has been no state change.
func (cache *snapshotCache) respondDelta(ctx context.Context, snapshot ResourceSnapshot, request *DeltaRequest, value chan DeltaResponse, sub Subscription) (*RawDeltaResponse, error) {
	resp := createDeltaResponse(ctx, request, sub, resourceContainer{
		resourceMap: snapshot.GetResources(request.GetTypeUrl()),
		versionMap:  snapshot.GetVersionMap(request.GetTypeUrl()),
	}, snapshot.GetVersion(request.GetTypeUrl()))

	// Only send a response if there were changes
	// We want to respond immediately for the first wildcard request in a stream, even if the response is empty
	// otherwise, envoy won't complete initialization
	if len(resp.resources) > 0 || len(resp.removedResources) > 0 || (sub.IsWildcard() && request.ResponseNonce == "") {
		if cache.log != nil {
			cache.log.Debugf("node: %s, sending delta response for typeURL %s with resources: %v removed resources: %v with wildcard: %t",
				request.GetNode().GetId(), request.GetTypeUrl(), getCachedResourceNames(resp.resources), resp.removedResources, sub.IsWildcard())
		}
		select {
		case value <- resp:
			return resp, nil
		case <-ctx.Done():
			return resp, context.Canceled
		}
	}
	return nil, nil
}

func (cache *snapshotCache) nextDeltaWatchID() int64 {
	return atomic.AddInt64(&cache.deltaWatchCount, 1)
}

// cancellation function for cleaning stale delta watches
func (cache *snapshotCache) cancelDeltaWatch(nodeID string, watchID int64) func() {
	return func() {
		cache.mu.RLock()
		defer cache.mu.RUnlock()
		if info, ok := cache.status[nodeID]; ok {
			info.mu.Lock()
			delete(info.deltaWatches, watchID)
			info.mu.Unlock()
		}
	}
}

// Fetch implements the cache fetch function.
// Fetch is called on multiple streams, so responding to individual names with the same version works.
func (cache *snapshotCache) Fetch(ctx context.Context, request *Request) (Response, error) {
	nodeID := cache.hash.ID(request.GetNode())

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	if snapshot, exists := cache.snapshots[nodeID]; exists {
		// Respond only if the request version is distinct from the current snapshot state.
		// It might be beneficial to hold the request since Envoy will re-attempt the refresh.
		version := snapshot.GetVersion(request.GetTypeUrl())
		if request.GetVersionInfo() == version {
			cache.log.Warnf("skip fetch: version up to date")
			return nil, &types.SkipFetchError{}
		}

		resources := snapshot.GetResourcesAndTTL(request.GetTypeUrl())
		out := createResponse(ctx, request, resources, version, false)
		return out, nil
	}

	return nil, fmt.Errorf("missing snapshot for %q", nodeID)
}

// GetStatusInfo retrieves the status info for the node.
func (cache *snapshotCache) GetStatusInfo(node string) StatusInfo {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	info, exists := cache.status[node]
	if !exists {
		cache.log.Warnf("node does not exist")
		return nil
	}

	return info
}

// GetStatusKeys retrieves all node IDs in the status map.
func (cache *snapshotCache) GetStatusKeys() []string {
	cache.mu.RLock()
	defer cache.mu.RUnlock()

	out := make([]string, 0, len(cache.status))
	for id := range cache.status {
		out = append(out, id)
	}

	return out
}
