// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

type StreamProcessorParams struct {
	// The backing gRPC bidi stream initiated by zTunnel
	Stream v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	// Channel where the StreamProcessor listens for new DeltaDiscoveryRequest.
	// this is fed directly from Stream.
	StreamRecv chan *v3.DeltaDiscoveryRequest
	// Channel where the StreamProcessor listens for Endpoint event.
	// this is fed by subscribing to EndpointManager.
	EndpointEventRecv chan *EndpointEvent
	// Reference to agent's CEP watcher and resource cache.
	// This will be the source of truth for serving WDS API.
	K8sCiliumEndpointsWatcher *watchers.K8sCiliumEndpointsWatcher
	Log                       *slog.Logger
}

// StreamProcessor implements the logic for handling xDS streams to zTunnel.
// It is abstracted away from the primary stream initialization handler to
// promote decoupling and the handling multiple streams without a shared set of
// channels being required on the Server object.
type StreamProcessor struct {
	stream         v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	streamRecv     chan *v3.DeltaDiscoveryRequest
	endpointRecv   chan *EndpointEvent
	expectedNonce  map[string]struct{}
	log            *slog.Logger
	endpointSource EndpointEventSource
}

// EndpointSource provides data for XDS server from different data sources in the agent.
type EndpointSource struct {
	k8sCiliumEndpointsWatcher *watchers.K8sCiliumEndpointsWatcher
	sp                        *StreamProcessor
}

func NewEndpointSource(k *watchers.K8sCiliumEndpointsWatcher, sp *StreamProcessor) *EndpointSource {
	return &EndpointSource{
		k8sCiliumEndpointsWatcher: k,
		sp:                        sp,
	}
}

// Interface different data sources need to implement for usage with StreamProcessor.
type EndpointEventSource interface {
	// Subscribe to Endpoint events.
	SubscribeToEndpointEvents(ctx context.Context, wg *sync.WaitGroup)
	ListAllEndpoints(ctx context.Context) ([]*types.CiliumEndpoint, error)
}

func NewStreamProcessor(params *StreamProcessorParams) *StreamProcessor {
	sp := &StreamProcessor{
		stream:        params.Stream,
		streamRecv:    params.StreamRecv,
		endpointRecv:  params.EndpointEventRecv,
		log:           params.Log,
		expectedNonce: make(map[string]struct{}),
	}
	sp.endpointSource = NewEndpointSource(params.K8sCiliumEndpointsWatcher, sp)
	return sp
}

// convertCESToEndpointMap converts a CiliumEndpointSlice to a map of CiliumEndpoints
// keyed by namespace/name for easy lookup and comparison.
func convertCESToEndpointMap(ces *v2alpha1.CiliumEndpointSlice) map[string]*types.CiliumEndpoint {
	result := make(map[string]*types.CiliumEndpoint, len(ces.Endpoints))
	for _, coreCep := range ces.Endpoints {
		cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&coreCep, ces.Namespace)
		cepName := cep.Namespace + "/" + cep.Name
		result[cepName] = cep
	}
	return result
}

// computeEndpointDiff compares old and new endpoint maps and returns lists of
// endpoints that were added, updated, or removed.
func computeEndpointDiff(oldCEPs, newCEPs map[string]*types.CiliumEndpoint) (added, updated, removed []*types.CiliumEndpoint) {
	// Find removed endpoints (in old but not in new)
	for cepName, oldCEP := range oldCEPs {
		if _, exists := newCEPs[cepName]; !exists {
			removed = append(removed, oldCEP)
		}
	}

	// Find new or updated endpoints
	for cepName, newCEP := range newCEPs {
		if oldCEP, exists := oldCEPs[cepName]; !exists {
			// New endpoint
			added = append(added, newCEP)
		} else if !oldCEP.DeepEqual(newCEP) {
			// Updated endpoint
			updated = append(updated, newCEP)
		}
	}

	return added, updated, removed
}

// emitEndpointEvents sends endpoint events to the event channel.
func (es *EndpointSource) emitEndpointEvents(eventType EndpointEventType, endpoints []*types.CiliumEndpoint) {
	for _, ep := range endpoints {
		es.sp.endpointRecv <- &EndpointEvent{
			Type:           eventType,
			CiliumEndpoint: ep,
		}
	}
}

// handleCESUpsert processes an upsert event for a CiliumEndpointSlice.
func (es *EndpointSource) handleCESUpsert(ces *v2alpha1.CiliumEndpointSlice, cesCache map[resource.Key]map[string]*types.CiliumEndpoint, key resource.Key) {
	oldCEPs := cesCache[key]
	if oldCEPs == nil {
		oldCEPs = make(map[string]*types.CiliumEndpoint)
	}

	newCEPs := convertCESToEndpointMap(ces)
	added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)

	// Emit events for changes
	es.emitEndpointEvents(REMOVED, removed)
	es.emitEndpointEvents(CREATE, added)
	es.emitEndpointEvents(CREATE, updated) // Updates are treated as CREATE

	// Update cache
	cesCache[key] = newCEPs
}

// handleCESDelete processes a delete event for a CiliumEndpointSlice.
func (es *EndpointSource) handleCESDelete(ces *v2alpha1.CiliumEndpointSlice, cesCache map[resource.Key]map[string]*types.CiliumEndpoint, key resource.Key) {
	endpoints := convertCESToEndpointMap(ces)
	endpointList := make([]*types.CiliumEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		endpointList = append(endpointList, ep)
	}
	es.emitEndpointEvents(REMOVED, endpointList)
	delete(cesCache, key)
}

func (es *EndpointSource) SubscribeToEndpointEvents(ctx context.Context, wg *sync.WaitGroup) {
	if option.Config.EnableCiliumEndpointSlice {
		newSliceEvents := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointSliceResource().Events(ctx, resource.WithErrorHandler(resource.AlwaysRetry))
		// Keep track of CEPs in each CES to detect deletions on updates
		cesCache := make(map[resource.Key]map[string]*types.CiliumEndpoint)

		for e := range newSliceEvents {
			if e.Kind == resource.Sync {
				wg.Done()
				e.Done(nil)
				continue
			}
			if e.Object == nil {
				e.Done(nil)
				continue
			}

			switch e.Kind {
			case resource.Upsert:
				es.handleCESUpsert(e.Object, cesCache, e.Key)
			case resource.Delete:
				es.handleCESDelete(e.Object, cesCache, e.Key)
			}

			e.Done(nil)
		}
		return
	}

	// TODO(hemanthmalla): How should retries be configured here ?
	newEvents := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointResource().Events(ctx, resource.WithErrorHandler(resource.AlwaysRetry))
	for e := range newEvents {
		switch e.Kind {
		case resource.Upsert:
			es.sp.endpointRecv <- &EndpointEvent{
				Type:           CREATE,
				CiliumEndpoint: e.Object,
			}
		case resource.Delete:
			es.sp.endpointRecv <- &EndpointEvent{
				Type:           REMOVED,
				CiliumEndpoint: e.Object,
			}
		case resource.Sync:
			wg.Done()
		}
		e.Done(nil)
	}
}

func (es *EndpointSource) ListAllEndpoints(ctx context.Context) ([]*types.CiliumEndpoint, error) {
	eps := []*types.CiliumEndpoint{}
	if option.Config.EnableCiliumEndpointSlice {
		cesStore, err := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointSliceResource().Store(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get CiliumEndpointSlice store from K8sCiliumEndpointsWatcher: %w", err)
		}
		slices := cesStore.List()

		for _, s := range slices {
			for _, ep := range s.Endpoints {
				cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ep, s.Namespace)
				eps = append(eps, cep)
			}
		}
		return eps, nil
	}

	cepStore, err := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointResource().Store(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get CiliumEndpoint store from K8sCiliumEndpointsWatcher: %w", err)
	}
	eps = cepStore.List()
	return eps, nil
}

// handleAddressTypeURL handles a subscription for xdsTypeURLAddress type URLs.
//
// On receit of this request from zTunnel we will send an initial seed of
// endpoints to ztunnel.
//
// Next, we will subscribe our StreamProcessor to the endpoint.EndpointManager
// to watch for new events.
//
// The main event loop with process any further endpoint events.
func (sp *StreamProcessor) handleAddressTypeURL(req *v3.DeltaDiscoveryRequest) error {
	// this must be a request to subscribe to all Address resources.
	//
	// in Istio an Address resource is either a Workload or a Service.
	// For now, we expect Cilium's socket-lb to be handling service translation,
	// so we will only send Workload events to support pod-to-pod proxying.
	if len(req.ResourceNamesSubscribe) != 0 && len(req.ResourceNamesUnsubscribe) != 0 {
		return fmt.Errorf("unexpected resource names subscribe %v or unsubscribe %v for Address type URL",
			req.ResourceNamesSubscribe, req.ResourceNamesUnsubscribe)
	}

	collection := &EndpointEventCollection{}

	eps, err := sp.endpointSource.ListAllEndpoints(sp.stream.Context())
	if err != nil {
		return err
	}

	// TODO: we need to filter our ztunnel instance itself.
	collection.AppendEndpoints(CREATE, eps)

	resp := collection.ToDeltaDiscoveryResponse()
	if err := sp.stream.SendMsg(resp); err != nil {
		return err
	}

	// record the generated Nonce so we can link up any Ack or Nack in our main
	// event loop.
	sp.expectedNonce[resp.Nonce] = struct{}{}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go sp.endpointSource.SubscribeToEndpointEvents(sp.stream.Context(), wg)
	// Wait for initial sync of endpoints before returning.
	// SubscribeToEndpointEvents will call wg.Done() on receiving a sync event.
	wg.Wait()

	sp.log.Debug("initialized new stream for resource", logfields.Resource, xdsTypeURLAddress)

	return nil
}

func (sp *StreamProcessor) handleAuthorizationTypeURL(_ *v3.DeltaDiscoveryRequest) error {
	// TODO: For MVP we do not handle Authorization policy requests.

	resp := &v3.DeltaDiscoveryResponse{
		TypeUrl:          xdsTypeURLAuthorization,
		Resources:        []*v3.Resource{},
		RemovedResources: []string{},
		Nonce:            "0", // static nonce as we do not expect any further requests
	}

	sp.expectedNonce["0"] = struct{}{}

	if err := sp.stream.SendMsg(resp); err != nil {
		return err
	}

	return nil
}

func (sp *StreamProcessor) handleDeltaDiscoveryReq(req *v3.DeltaDiscoveryRequest) error {
	// if the delta discovery request has a nonce, this is a ack or nack.
	// for now, if we have a Nack we'll log the errors, retrying a Nack'd
	// message would cause the same issue as previously encountered.
	if req.ResponseNonce != "" {
		// check if this is an expected nonce, if not, its an error
		if _, ok := sp.expectedNonce[req.ResponseNonce]; !ok {
			return fmt.Errorf("unexpected nonce %q received", req.ResponseNonce)
		}

		// remove expected Nonce
		delete(sp.expectedNonce, req.ResponseNonce)

		if req.ErrorDetail != nil {
			sp.log.Error("Nack received from ztunnel",
				logfields.Error,
				req.ErrorDetail.Message,
				logfields.Code,
				req.ErrorDetail.Code)
			// return nil here, we did not encounter a stream error,
			// instead we log the Nack to display an application level error.
			return nil
		}
		return nil
	}

	// there is no nonce so we have a subscription request for a particular
	// resource type. ztunnel will only subscribe to two types of events.
	switch req.TypeUrl {
	case xdsTypeURLAddress:
		return sp.handleAddressTypeURL(req)
	case xdsTypeURLAuthorization:
		return sp.handleAuthorizationTypeURL(req)
	default:
		return fmt.Errorf("unexpected type URL %q, expected %q or %q", req.TypeUrl, xdsTypeURLAddress, xdsTypeURLAuthorization)
	}

}

func (sp *StreamProcessor) handleEPEvent(epEvent *EndpointEvent) error {
	collection := EndpointEventCollection{epEvent}

drained:
	for {
		select {
		case ep := <-sp.endpointRecv:
			collection = append(collection, ep)
		default:
			break drained
		}
	}

	resp := collection.ToDeltaDiscoveryResponse()

	// record the generated Nonce so we can link up any Ack or Nack in our main
	// event loop.
	sp.expectedNonce[resp.Nonce] = struct{}{}

	err := sp.stream.SendMsg(resp)
	if err != nil {
		return err
	}
	return nil
}

// Start will begin processing both xDS and Endpoint stream events and push the
// required information to the client stream.
//
// The internal event loop will halt when the stream's context is canceled
// This will occur when the client closes the stream or any halting error is
// encountered, such as on SendMsg().
//
// This function spawns one additional goroutine which is destroyed when
// the stream is hatled.
func (sp *StreamProcessor) Start() {
	// goroutine to feed our streamRecv channel
	go func() {
		for {
			// goroutine exit condition
			if err := sp.stream.Context().Err(); err != nil {
				return
			}
			streamReq, err := sp.stream.Recv()
			if err != nil {
				sp.log.Error(
					"Failed to receive DeltaDiscoveryRequest from stream",
					logfields.Error, err)
				return
			}
			sp.streamRecv <- streamReq
		}
	}()

	// the event loop for stream processing
	for {
		select {
		// event loop exit condition
		case <-sp.stream.Context().Done():
			sp.log.Error("Stream context done with error", logfields.Error,
				sp.stream.Context().Err())
			return
		// new request from ztunnel
		case streamReq := <-sp.streamRecv:
			if err := sp.handleDeltaDiscoveryReq(streamReq); err != nil {
				sp.log.Error("Failed to handle DeltaDiscoveryRequest",
					logfields.Error, err)
			}
		// new event from CEP/CES cache store.
		case epEvent := <-sp.endpointRecv:
			if err := sp.handleEPEvent(epEvent); err != nil {
				sp.log.Error("Failed to handle EndpointEvent",
					logfields.Error,
					err,
					logfields.EndpointID,
					epEvent.UID)
			}
		}
	}
}
