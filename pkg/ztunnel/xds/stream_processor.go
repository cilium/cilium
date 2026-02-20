// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"log/slog"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/ztunnel/table"
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
	DB                        *statedb.DB
	EnrolledNamespaceTable    statedb.RWTable[*table.EnrolledNamespace]
	Log                       *slog.Logger
}

// StreamProcessor implements the logic for handling xDS streams to zTunnel.
// It is abstracted away from the primary stream initialization handler to
// promote decoupling and the handling multiple streams without a shared set of
// channels being required on the Server object.
type StreamProcessor struct {
	stream                 v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	streamRecv             chan *v3.DeltaDiscoveryRequest
	endpointRecv           chan *EndpointEvent
	expectedNonce          map[string]struct{}
	log                    *slog.Logger
	endpointSource         EndpointEventSource
	db                     *statedb.DB
	enrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
}

// CiliumEndpointsWatcher defines the interface for watching CiliumEndpoints and CiliumEndpointSlices.
// This interface enables mocking for testing purposes.
type CiliumEndpointsWatcher interface {
	GetCiliumEndpointResource() resource.Resource[*types.CiliumEndpoint]
	GetCiliumEndpointSliceResource() resource.Resource[*v2alpha1.CiliumEndpointSlice]
}

// Ensure watchers.K8sCiliumEndpointsWatcher implements CiliumEndpointsWatcher.
var _ CiliumEndpointsWatcher = (*watchers.K8sCiliumEndpointsWatcher)(nil)

// EndpointSource provides data for XDS server from different data sources in the agent.
type EndpointSource struct {
	k8sCiliumEndpointsWatcher CiliumEndpointsWatcher
	sp                        *StreamProcessor
}

func NewEndpointSource(k *watchers.K8sCiliumEndpointsWatcher, sp *StreamProcessor) *EndpointSource {
	return &EndpointSource{
		k8sCiliumEndpointsWatcher: k,
		sp:                        sp,
	}
}

// isNamespaceEnrolled checks if the given namespace is enrolled for ztunnel processing.
func (es *EndpointSource) isNamespaceEnrolled(namespace string) bool {
	txn := es.sp.db.ReadTxn()
	_, _, found := es.sp.enrolledNamespaceTable.Get(txn, table.EnrolledNamespacesNameIndex.Query(namespace))
	return found
}

// Interface different data sources need to implement for usage with StreamProcessor.
type EndpointEventSource interface {
	// SubscribeToEndpointEvents subscribes to endpoint events.
	// Pre-Sync replay events are buffered and sent as an EndpointEventCollection
	// on syncCh. Post-Sync events are forwarded to endpointRecv individually.
	// syncCh is closed when the subscription ends.
	SubscribeToEndpointEvents(ctx context.Context, syncCh chan<- EndpointEventCollection)
}

func NewStreamProcessor(params *StreamProcessorParams) *StreamProcessor {
	sp := &StreamProcessor{
		stream:                 params.Stream,
		streamRecv:             params.StreamRecv,
		endpointRecv:           params.EndpointEventRecv,
		log:                    params.Log,
		expectedNonce:          make(map[string]struct{}),
		db:                     params.DB,
		enrolledNamespaceTable: params.EnrolledNamespaceTable,
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
// Checks stream context before each send to bail out on cancellation.
func (es *EndpointSource) emitEndpointEvents(eventType EndpointEventType, endpoints []*types.CiliumEndpoint) {
	for _, ep := range endpoints {
		if es.sp.stream != nil && es.sp.stream.Context().Err() != nil {
			return
		}
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

func (es *EndpointSource) SubscribeToEndpointEvents(ctx context.Context, syncCh chan<- EndpointEventCollection) {
	defer close(syncCh)

	if option.Config.EnableCiliumEndpointSlice {
		newSliceEvents := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointSliceResource().Events(ctx, resource.WithErrorHandler(resource.AlwaysRetry))
		// Keep track of CEPs in each CES to detect deletions on updates
		cesCache := make(map[resource.Key]map[string]*types.CiliumEndpoint)
		var synced bool
		var initialBatch EndpointEventCollection

		for e := range newSliceEvents {
			if ctx.Err() != nil {
				e.Done(nil)
				return
			}
			if e.Kind == resource.Sync {
				if !synced {
					syncCh <- initialBatch
					synced = true
				}
				e.Done(nil)
				continue
			}
			if e.Object == nil {
				e.Done(nil)
				continue
			}

			if !es.isNamespaceEnrolled(e.Object.Namespace) {
				es.sp.log.Debug("Skipping processing of CiliumEndpointSlice in unenrolled namespace",
					logfields.K8sNamespace, e.Object.Namespace,
					logfields.Name, e.Object.GetName(),
				)
				e.Done(nil)
				continue
			}

			if !synced {
				// Buffer pre-Sync events into the initial batch
				oldCEPs := cesCache[e.Key]
				if oldCEPs == nil {
					oldCEPs = make(map[string]*types.CiliumEndpoint)
				}
				newCEPs := convertCESToEndpointMap(e.Object)

				switch e.Kind {
				case resource.Upsert:
					added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)
					initialBatch.AppendEndpoints(REMOVED, removed)
					initialBatch.AppendEndpoints(CREATE, added)
					initialBatch.AppendEndpoints(CREATE, updated)
					cesCache[e.Key] = newCEPs
				case resource.Delete:
					endpointList := make([]*types.CiliumEndpoint, 0, len(newCEPs))
					for _, ep := range newCEPs {
						endpointList = append(endpointList, ep)
					}
					initialBatch.AppendEndpoints(REMOVED, endpointList)
					delete(cesCache, e.Key)
				}
			} else {
				switch e.Kind {
				case resource.Upsert:
					es.handleCESUpsert(e.Object, cesCache, e.Key)
				case resource.Delete:
					es.handleCESDelete(e.Object, cesCache, e.Key)
				}
			}

			e.Done(nil)
		}
		return
	}

	// TODO(hemanthmalla): How should retries be configured here ?
	newEvents := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointResource().Events(ctx, resource.WithErrorHandler(resource.AlwaysRetry))
	var synced bool
	var initialBatch EndpointEventCollection

	for e := range newEvents {
		if ctx.Err() != nil {
			e.Done(nil)
			return
		}
		if e.Kind == resource.Sync {
			if !synced {
				syncCh <- initialBatch
				synced = true
			}
			e.Done(nil)
			continue
		}
		if e.Object == nil {
			e.Done(nil)
			continue
		}

		if !es.isNamespaceEnrolled(e.Object.GetNamespace()) {
			es.sp.log.Debug("Skipping processing of CiliumEndpoint in unenrolled namespace",
				logfields.K8sNamespace, e.Object.GetNamespace(),
				logfields.Name, e.Object.GetName(),
			)
			e.Done(nil)
			continue
		}

		if !synced {
			// Buffer pre-Sync events into the initial batch
			switch e.Kind {
			case resource.Upsert:
				initialBatch = append(initialBatch, &EndpointEvent{
					Type:           CREATE,
					CiliumEndpoint: e.Object,
				})
			case resource.Delete:
				initialBatch = append(initialBatch, &EndpointEvent{
					Type:           REMOVED,
					CiliumEndpoint: e.Object,
				})
			}
		} else {
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
			}
		}
		e.Done(nil)
	}
}

// handleAddressTypeURL handles a subscription for xdsTypeURLAddress type URLs.
//
// On receipt of this request from zTunnel we subscribe our StreamProcessor to
// endpoint events and wait for the initial sync to complete. The subscription
// buffers all replayed events until Sync, then delivers them as a single
// atomic xDS response so ztunnel receives the full snapshot before becoming
// ready.
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

	ctx := sp.stream.Context()

	// Subscribe to endpoint events. The subscription buffers all replayed
	// events until the initial Sync, then sends the batch on syncCh.
	// Post-Sync events are forwarded to endpointRecv individually.
	syncCh := make(chan EndpointEventCollection, 1)
	go sp.endpointSource.SubscribeToEndpointEvents(ctx, syncCh)

	// Wait for the initial batch from the subscription replay so that
	// ztunnel receives all existing workloads atomically in one response.
	var collection EndpointEventCollection
	select {
	case batch, ok := <-syncCh:
		if ok {
			collection = batch
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	resp := collection.ToDeltaDiscoveryResponse()
	sp.expectedNonce[resp.Nonce] = struct{}{}

	if err := sp.stream.SendMsg(resp); err != nil {
		return err
	}

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
