// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/pkg/container/set"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

type nodeDeltaWatchState = typeurl.Map[set.Set[*trackedDeltaWatch]]

// deltaWatchRelay buffers go-control-plane responses while cache locks are held
// so Cilium can capture coverage and claim rollback ownership before delivery.
// Forwarding to the stream happens after unlocking; one relay per response
// channel lets delivery order each batch without forwarding goroutines.
type deltaWatchRelay struct {
	inner   chan cache.DeltaResponse
	outer   chan cache.DeltaResponse
	watches set.Set[*trackedDeltaWatch]
}

type trackedDeltaWatch struct {
	state        *nodeState
	typeURL      typeurl.Index
	streamID     int64
	request      *cache.DeltaRequest
	subscription cache.Subscription
	relay        *deltaWatchRelay
	cancel       func()
	deliverySync[cache.DeltaResponse]
}

type deltaWatchResponse struct {
	cache.DeltaResponse
	watch *trackedDeltaWatch
}

type deltaResponseDelivery struct {
	channel   chan cache.DeltaResponse
	responses []deltaWatchResponse
}

type versionedDeltaResponse struct {
	cache.DeltaResponse
	marshal   func() (*discovery.DeltaDiscoveryResponse, error)
	callbacks *callbacks.CompletionCallbacks
	streamID  int64
}

func (response *versionedDeltaResponse) GetDeltaDiscoveryResponse() (*discovery.DeltaDiscoveryResponse, error) {
	wire, err := response.marshal()
	if err == nil {
		response.callbacks.RegisterDeltaResponse(response.streamID, wire, response.GetContext())
	}
	return wire, err
}

// withDeltaSnapshotVersions serializes only the changes captured at publication.
// Native go-control-plane serialization would hash every resource, discarding
// Cilium's opaque versions and requiring another pass to rewrite the response.
func (c *cacheImpl) withDeltaSnapshotVersions(response cache.DeltaResponse, streamID int64) cache.DeltaResponse {
	resources, changes := callbacks.DeltaResponseChanges(response)
	if changes == nil {
		return response
	}
	return &versionedDeltaResponse{
		DeltaResponse: response,
		callbacks:     c.completionCbs,
		streamID:      streamID,
		marshal: sync.OnceValues(func() (*discovery.DeltaDiscoveryResponse, error) {
			typeURL := response.GetDeltaRequest().GetTypeUrl()
			wire := &discovery.DeltaDiscoveryResponse{
				TypeUrl:           typeURL,
				SystemVersionInfo: response.GetResponseVersion(),
				Resources:         make([]*discovery.Resource, 0, len(changes)),
			}
			for name, version := range changes {
				if version == "" {
					wire.RemovedResources = append(wire.RemovedResources, name)
					continue
				}
				resource, found := resources[name]
				if !found || resource.Resource == nil {
					return nil, fmt.Errorf("missing Delta resource %q at version %q", name, version)
				}
				encoded, err := cache.MarshalResource(resource.Resource)
				if err != nil {
					return nil, fmt.Errorf("marshaling Delta resource %q: %w", name, err)
				}
				item := &discovery.Resource{
					Name: name, Version: version,
					Resource: &anypb.Any{TypeUrl: typeURL, Value: encoded},
				}
				if resource.TTL != nil {
					item.Ttl = durationpb.New(*resource.TTL)
				}
				wire.Resources = append(wire.Resources, item)
			}
			return wire, nil
		}),
	}
}

func (c *cacheImpl) deltaRelayForLocked(responseChannel chan cache.DeltaResponse) *deltaWatchRelay {
	if relay := c.deltaWatchRelays[responseChannel]; relay != nil {
		return relay
	}
	capacity := max(cap(responseChannel), int(typeurl.Count)+1)
	relay := &deltaWatchRelay{
		inner: make(chan cache.DeltaResponse, capacity),
		outer: responseChannel,
	}
	c.deltaWatchRelays[responseChannel] = relay
	return relay
}

func (c *cacheImpl) addTrackedDeltaWatchLocked(state *nodeState, request *cache.DeltaRequest, subscription cache.Subscription, typeURL typeurl.Index, responseChannel chan cache.DeltaResponse) *trackedDeltaWatch {
	relay := c.deltaRelayForLocked(responseChannel)
	watch := &trackedDeltaWatch{
		state:        state,
		typeURL:      typeURL,
		streamID:     c.completionCbs.StreamIDForDeltaRequest(request),
		request:      request,
		subscription: subscription,
		relay:        relay,
	}
	watches, _ := state.openDeltaWatches.Get(typeURL)
	watches.Insert(watch)
	state.openDeltaWatches.Set(typeURL, watches)
	relay.watches.Insert(watch)
	return watch
}

func (c *cacheImpl) removeTrackedDeltaWatchLocked(watch *trackedDeltaWatch) {
	if watch == nil {
		return
	}
	watches, exists := watch.state.openDeltaWatches.Get(watch.typeURL)
	if exists {
		watches.Remove(watch)
		if watches.Empty() {
			watch.state.openDeltaWatches.Remove(watch.typeURL)
		} else {
			watch.state.openDeltaWatches.Set(watch.typeURL, watches)
		}
	}
	if watch.relay != nil {
		watch.relay.watches.Remove(watch)
		if watch.relay.watches.Empty() && len(watch.relay.inner) == 0 {
			delete(c.deltaWatchRelays, watch.relay.outer)
		}
	}
}

func (c *cacheImpl) cancelTrackedDeltaWatch(watch *trackedDeltaWatch) {
	c.mutex.Lock()
	var cancel func()
	if watch.relay.watches.Has(watch) {
		cancel = watch.cancel
		c.removeTrackedDeltaWatchLocked(watch)
	}
	hasDelivery := watch.cancelDeliveryLocked()
	c.mutex.Unlock()

	if hasDelivery {
		// go-control-plane's Delta implementation cancels all watches before
		// closing its shared response channel. Wait so a collected or blocked
		// send cannot race with that close. SotW leaves response channels open.
		watch.waitForDelivery()
	}
	// go-control-plane cancellation also runs outside the cache lock.
	if cancel != nil {
		cancel()
	}
}

func (c *cacheImpl) collectDeltaResponseDeliveriesLocked() []deltaResponseDelivery {
	var deliveries []deltaResponseDelivery
	for _, relay := range c.deltaWatchRelays {
		var responses []deltaWatchResponse
		for {
			select {
			case response := <-relay.inner:
				var matched *trackedDeltaWatch
				for watch := range relay.watches.Members() {
					if watch.request == response.GetDeltaRequest() {
						matched = watch
						break
					}
				}
				if matched == nil {
					// go-control-plane may queue a response after Cilium has
					// removed its canceled watch. It has no live consumer.
					continue
				}
				state := matched.state
				snapshot, _ := c.snapshotCache.GetSnapshot(state.nodeID)
				response = callbacks.WithDeltaResponseCoverage(response, state.snapshotGeneration, snapshot, matched.subscription)
				response = c.withDeltaSnapshotVersions(response, matched.streamID)
				matched.deliveryCanceled = make(chan struct{})
				responses = append(responses, deltaWatchResponse{DeltaResponse: response, watch: matched})
				state.rollbacks.claimResponseLocked(c, state, matched.typeURL, response)
				c.removeTrackedDeltaWatchLocked(matched)
			default:
				// A canceled watch may have left the last queued response.
				if relay.watches.Empty() {
					delete(c.deltaWatchRelays, relay.outer)
				}
				if len(responses) != 0 {
					deliveries = append(deliveries, deltaResponseDelivery{
						channel: relay.outer, responses: responses,
					})
				}
				goto nextRelay
			}
		}
	nextRelay:
	}
	return deliveries
}

func (c *cacheImpl) deliverDeltaResponses(deliveries []deltaResponseDelivery) {
	for _, delivery := range deliveries {
		// Preserve ADS dependency order within a publication, matching SotW
		// delivery from the same non-ADS snapshot cache.
		if len(delivery.responses) > 1 {
			slices.SortStableFunc(delivery.responses, func(a, b deltaWatchResponse) int {
				return cmp.Compare(cache.GetResponseType(a.GetDeltaRequest().GetTypeUrl()), cache.GetResponseType(b.GetDeltaRequest().GetTypeUrl()))
			})
		}
		for _, response := range delivery.responses {
			response.watch.deliverResponse(delivery.channel, response.DeltaResponse)
		}
	}
}

// CreateDeltaWatch tracks Delta responses with the same publication and
// rollback boundaries used by SotW ADS.
func (c *cacheImpl) CreateDeltaWatch(request *cache.DeltaRequest, subscription cache.Subscription, responseChannel chan cache.DeltaResponse) (cancel func(), err error) {
	if !c.deltaADS {
		return c.snapshotCache.CreateDeltaWatch(request, subscription, responseChannel)
	}
	if request == nil {
		return nil, errors.New("nil Delta xDS request")
	}
	nodeID := request.GetNode().GetId()
	state := c.getNodeState(nodeID)
	if state == nil {
		return nil, fmt.Errorf("unknown xDS node %q", nodeID)
	}
	if subscription == nil {
		return c.snapshotCache.CreateDeltaWatch(request, subscription, responseChannel)
	}
	typeURL, supported := typeurl.FromURL(request.GetTypeUrl())
	if !supported {
		return c.snapshotCache.CreateDeltaWatch(request, subscription, responseChannel)
	}
	if !subscription.IsWildcard() && len(subscription.SubscribedResources()) == 0 {
		return func() {}, nil
	}

	c.mutex.Lock()
	if err := state.selectEpochLocked(typeURL, maps.Values(request.GetInitialResourceVersions())); err != nil {
		c.mutex.Unlock()
		return nil, err
	}
	finalized, err := c.prepareLiveSnapshotLocked(state, typeURL)
	if err != nil {
		deliveries := c.collectResponseDeliveriesLocked()
		deltaDeliveries := c.collectDeltaResponseDeliveriesLocked()
		c.mutex.Unlock()
		c.deliverResponses(deliveries)
		c.deliverDeltaResponses(deltaDeliveries)
		c.completeFinalized(nodeID, finalized)
		return nil, err
	}
	state.commitEpochNegotiation(typeURL)
	watch := c.addTrackedDeltaWatchLocked(state, request, subscription, typeURL, responseChannel)
	watch.cancel, err = c.snapshotCache.CreateDeltaWatch(request, subscription, watch.relay.inner)
	if err != nil {
		c.removeTrackedDeltaWatchLocked(watch)
	}
	deliveries := c.collectResponseDeliveriesLocked()
	deltaDeliveries := c.collectDeltaResponseDeliveriesLocked()
	c.mutex.Unlock()
	c.deliverResponses(deliveries)
	c.deliverDeltaResponses(deltaDeliveries)
	c.completeFinalized(nodeID, finalized)
	if err != nil {
		return nil, err
	}
	return func() { c.cancelTrackedDeltaWatch(watch) }, nil
}
