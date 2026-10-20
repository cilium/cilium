// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"errors"
	"fmt"
	"maps"

	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/cilium/cilium/pkg/container/set"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

type nodeDeltaWatchState = typeurl.Map[set.Set[*trackedDeltaWatch]]

type deltaWatchRelay struct {
	inner   chan cache.DeltaResponse
	outer   chan cache.DeltaResponse
	watches set.Set[*trackedDeltaWatch]
}

type trackedDeltaWatch struct {
	state        *nodeState
	typeURL      typeurl.Index
	request      *cache.DeltaRequest
	subscription cache.Subscription
	relay        *deltaWatchRelay
	cancel       func()
}

func (watch *trackedDeltaWatch) isOpen() bool {
	return watch != nil && watch.relay != nil && watch.relay.watches.Has(watch)
}

type deltaResponseDelivery struct {
	channel   chan cache.DeltaResponse
	responses []cache.DeltaResponse
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
	if !watch.isOpen() {
		c.mutex.Unlock()
		return
	}
	cancel := watch.cancel
	c.removeTrackedDeltaWatchLocked(watch)
	c.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *cacheImpl) collectDeltaResponseDeliveriesLocked() []deltaResponseDelivery {
	var deliveries []deltaResponseDelivery
	for _, relay := range c.deltaWatchRelays {
		var responses []cache.DeltaResponse
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
				nodeID := response.GetDeltaRequest().GetNode().GetId()
				state := c.getNodeState(nodeID)
				if state != nil {
					snapshot, _ := c.snapshotCache.GetSnapshot(nodeID)
					var subscription cache.Subscription
					if matched != nil {
						subscription = matched.subscription
					}
					response = callbacks.WithDeltaResponseCoverage(response, state.snapshotGeneration, snapshot, subscription)
				}
				responses = append(responses, response)
				if matched != nil {
					matched.state.rollbacks.claimResponseLocked(c, matched.state, matched.typeURL, response)
					c.removeTrackedDeltaWatchLocked(matched)
				}
			default:
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
		for _, response := range delivery.responses {
			c.completionCbs.RegisterDeltaResponse(response)
			delivery.channel <- response
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
