// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	// AnyTypeURL is the default type URL to use for ADS resource sets.
	AnyTypeURL = ""
)

var (
	// ErrNoADSTypeURL is the error returned when receiving a request without
	// a type URL from an ADS stream.
	ErrNoADSTypeURL = errors.New("type URL is required for ADS")

	// ErrMismatchingTypeURL is the error returned when receiving a request with
	// an unexpected type URL.
	ErrMismatchingTypeURL = errors.New("mismatching type URL")

	// ErrUnknownTypeURL is the error returned when receiving a request with
	// an unknown type URL.
	ErrUnknownTypeURL = errors.New("unknown type URL")

	// ErrInvalidVersionInfo is the error returned when receiving a request
	// with a version info that is not a positive integer.
	ErrInvalidVersionInfo = errors.New("invalid version info")

	// ErrInvalidNonce is the error returned when receiving a request
	// with a response nonce that is not a positive integer.
	ErrInvalidResponseNonce = errors.New("invalid response nonce info")

	// ErrInvalidNodeFormat is the error returned when receiving a request
	// with a node that is not a formatted correctly.
	ErrInvalidNodeFormat = errors.New("invalid node format")

	// ErrResourceWatch is the error returned whenever an internal error
	// occurs while waiting for new versions of resources.
	ErrResourceWatch = errors.New("resource watch failed")

	// grpcCanceled is the string prefix of any gRPC error related
	// to the stream being canceled. Ignore the description, as it
	// is derived from the client and may vary, while the code is
	// set by the gRPC library we link with.
	//
	// Ref. vendor/google.golang.org/grpc/status/status.go:
	// return fmt.Sprintf("rpc error: code = %s desc = %s", codes.Code(p.GetCode()), p.GetMessage())
	grpcCanceled = fmt.Sprintf("rpc error: code = %s", codes.Canceled.String())
)

// Server implements the handling of xDS streams.
type Server struct {
	logger *slog.Logger
	// sources maps each supported type URL to its corresponding resource source.
	sources map[string]ResourceSource

	// ackObservers maps each supported type URL to its corresponding observer
	// of ACKs received from Envoy nodes.
	ackObservers map[string]ResourceVersionAckObserver

	// lastStreamID is the identifier of the last processed stream.
	// It is incremented atomically when starting the handling of a new stream.
	lastStreamID atomic.Uint64

	metrics Metrics
}

// ResourceTypeConfiguration is the configuration of the XDS server for a
// resource type.
type ResourceTypeConfiguration struct {
	// Source contains the resources of this type.
	Source ResourceSource

	// AckObserver is called back whenever a node acknowledges having applied a
	// version of the resources of this type.
	AckObserver ResourceVersionAckObserver
}

// NewServer creates an xDS gRPC stream handler using the given resource
// sources.
// types maps each supported resource type URL to its corresponding resource
// source and ACK observer.
func NewServer(logger *slog.Logger, resourceTypes map[string]*ResourceTypeConfiguration, restorerPromise promise.Promise[endpointstate.Restorer], metrics Metrics) *Server {
	sources := make(map[string]ResourceSource, len(resourceTypes))
	ackObservers := make(map[string]ResourceVersionAckObserver, len(resourceTypes))
	for typeURL, resType := range resourceTypes {
		sources[typeURL] = resType.Source

		if resType.AckObserver != nil {
			if restorerPromise != nil {
				resType.AckObserver.MarkRestorePending()
			}
			ackObservers[typeURL] = resType.AckObserver
		}
	}

	return &Server{logger: logger, sources: sources, ackObservers: ackObservers, metrics: metrics}
}

func (s *Server) RestoreCompleted() {
	for _, ackObserver := range s.ackObservers {
		ackObserver.MarkRestoreCompleted()
	}
}

func getXDSRequestFields(req *envoy_service_discovery.DiscoveryRequest) []any {
	return []any{
		logfields.Version, req.GetVersionInfo(),
		logfields.XDSTypeURL, req.GetTypeUrl(),
		logfields.XDSNonce, req.GetResponseNonce(),
	}
}

// HandleRequestStream receives and processes the requests from an xDS stream.
func (s *Server) HandleRequestStream(ctx context.Context, stream Stream, defaultTypeURL, afterTypeURL string) error {
	// increment stream count
	streamID := s.lastStreamID.Add(1)

	reqStreamLog := s.logger.With(logfields.XDSStreamID, streamID)

	reqCh := make(chan *envoy_service_discovery.DiscoveryRequest)

	stopRecv := make(chan struct{})
	defer close(stopRecv)

	nodeId := ""

	go func(streamLog *slog.Logger) {
		defer close(reqCh)
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					streamLog.Debug("xDS stream closed")
				} else if strings.HasPrefix(err.Error(), grpcCanceled) {
					streamLog.Debug("xDS stream canceled", logfields.Error, err)
				} else {
					streamLog.Error("error while receiving request from xDS stream", logfields.Error, err)
				}
				return
			}
			if req == nil {
				streamLog.Error("received nil request from xDS stream; stopping xDS stream handling")
				return
			}
			if req.GetTypeUrl() == "" {
				req.TypeUrl = defaultTypeURL
			}
			if nodeId == "" {
				nodeId = req.GetNode().GetId()
				streamLog = streamLog.With(logfields.XDSClientNode, nodeId)
			}
			streamLog.Debug("received request from xDS stream", getXDSRequestFields(req)...)

			select {
			case <-stopRecv:
				streamLog.Debug("stopping xDS stream handling")
				return
			case reqCh <- req:
			}
		}
	}(reqStreamLog)

	return s.processRequestStream(ctx, reqStreamLog, stream, reqCh, defaultTypeURL, afterTypeURL)
}

// perTypeStreamState is the common state maintained per resource type for each
// xDS stream.
type perTypeStreamState struct {
	// typeURL identifies the resource type.
	typeURL string

	// pendingWatchCancel is a pending watch on this resource type.
	// If nil, no watch is pending.
	pendingWatchCancel context.CancelFunc

	// pendingWatchDone is closed when the pending watch has finished.
	pendingWatchDone <-chan struct{}
}

// perSotwTypeStreamState is the state maintained per resource type for each
// state-of-the-world xDS stream.
type perSotwTypeStreamState struct {
	perTypeStreamState

	// clientReceivedFirstResponse tracks whether this stream has already sent a
	// response for this type. This state must stay per-type so ADS streams do
	// not leak nonce handling across multiplexed resource types.
	clientReceivedFirstResponse bool

	// responseAcked tracks whether this stream has seen at least one ACK for
	// this type. This also stays per-type so ACK observer state does not leak
	// across multiplexed ADS resource types.
	responseAcked bool

	// resourceNames is the list of names of resources sent in the last
	// response to a request for this resource type.
	resourceNames []string

	// requestedResourceNames is the normalized set of names requested in the
	// last DiscoveryRequest for this resource type. Nil is the canonical form
	// for "all resources".
	// A pending watch may hold a read-only reference to this slice, so this
	// must not be mutated until the pending watch has finished.
	requestedResourceNames []string
}

func (state *perTypeStreamState) cancelPendingWatch() {
	if state.pendingWatchCancel != nil {
		state.pendingWatchCancel()
		if state.pendingWatchDone != nil {
			<-state.pendingWatchDone
		}
		state.pendingWatchCancel = nil
		state.pendingWatchDone = nil
	}
}

// updateRequestedResources updates the stored requested resource names and reports if the expressed
// interest was expanded.
func (s *perSotwTypeStreamState) updateRequestedResources(current []string) bool {
	// normalize 'current'
	if len(current) == 0 {
		current = nil
	} else {
		current = slices.Clone(current)
		slices.Sort(current)
		current = slices.Compact(current)
	}

	previous := s.requestedResourceNames
	s.requestedResourceNames = current

	// return true only if current is an expansion of interest in comparison to previous,
	// as then an immediate response is required
	if len(current) == 0 {
		// all resources requested, this is an expansion of interest if previous interest
		// was for a subset
		return len(previous) > 0
	}
	if len(previous) == 0 {
		return false
	}

	i := 0
	for _, name := range current {
		for i < len(previous) && previous[i] < name {
			i++
		}
		if i == len(previous) || previous[i] != name {
			// name not in previous, have expansion of interest
			return true
		}
	}
	return false
}

// processRequestStream processes the requests in an xDS stream from a channel.
func (s *Server) processRequestStream(ctx context.Context, streamLog *slog.Logger, stream Stream,
	reqCh <-chan *envoy_service_discovery.DiscoveryRequest, defaultTypeURL, afterTypeURL string,
) error {
	// The request state for every type URL.
	typeStates := make([]perSotwTypeStreamState, len(s.sources))
	defer func() {
		for i := range typeStates {
			typeStates[i].cancelPendingWatch()
		}
	}()

	// A map of a resource type's URL to the corresponding index in typeStates
	// for the resource type.
	typeIndexes := make(map[string]int, len(typeStates))

	// The set of channels to select from. Since the set of channels is
	// dynamic, we use reflection for selection.
	// The indexes in selectCases from 0 to len(typeStates)-1 match the indexes
	// in typeStates.
	selectCases := make([]reflect.SelectCase, len(typeStates)+2)

	// The last select case index is always the request channel.
	reqChIndex := len(selectCases) - 1
	selectCases[reqChIndex] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(reqCh),
	}

	// The next-to-last select case is the context's Done channel.
	doneChIndex := reqChIndex - 1
	selectCases[doneChIndex] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	}

	// Initially there are no pending watches, so just select a dead channel
	// that will never be selected.
	quietCh := make(chan *VersionedResources)
	defer close(quietCh)
	quietChValue := reflect.ValueOf(quietCh)

	i := 0
	for typeURL := range s.sources {
		typeStates[i] = perSotwTypeStreamState{
			perTypeStreamState: perTypeStreamState{
				typeURL: typeURL,
			},
		}

		selectCases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: quietChValue,
		}

		typeIndexes[typeURL] = i

		i++
	}

	streamLog.Info("starting xDS stream processing", logfields.XDSTypeURL, defaultTypeURL)

	// stream-scoped state
	nodeIP := ""
	firstRequest := true
	scopedLogger := streamLog

	for {
		// Process either a new request from the xDS stream or a response
		// from the resource watcher.
		chosen, recv, recvOK := reflect.Select(selectCases)

		switch chosen {
		case doneChIndex: // Context got canceled, most likely by the client terminating.
			scopedLogger.Debug("xDS stream context canceled", logfields.Error, ctx.Err())
			return nil

		case reqChIndex: // Request received from the stream.
			if !recvOK {
				scopedLogger.Info("xDS stream closed")
				return nil
			}

			req := recv.Interface().(*envoy_service_discovery.DiscoveryRequest)

			// only require Node to exist in the first request
			if firstRequest {
				id := req.GetNode().GetId()
				scopedLogger = streamLog.With(logfields.XDSClientNode, id)
				var err error
				nodeIP, err = EnvoyNodeIdToIP(id)
				if err != nil {
					scopedLogger.Error("invalid Node in xDS request", logfields.Error, err)
					return ErrInvalidNodeFormat
				}
				scopedLogger.Info("Received first request in a new xDS stream", getXDSRequestFields(req)...)

				// delay responding to the first request until 'afterTypeURL' has
				// been acked, if any
				if afterTypeURL != "" {
					s.ackObservers[afterTypeURL].WaitForFirstAck(ctx, nodeIP, afterTypeURL)
				}
			}

			requestLog := scopedLogger.With(getXDSRequestFields(req)...)

			// VersionInfo is property of resources,
			// while nonce is property of the stream.
			// VersionInfo is only empty for a new client instance that did not
			// receive any ACKed version of resources previously.
			// In case of xDS server restart (cilium-agent),
			// Envoy will send a request with VersionInfo set to the last ACKed version
			// it received. Additionally, nonce will be empty.

			// lastAckedVersion is the latest version the client has successfully
			// applied.
			var lastAckedVersion uint64
			if req.GetVersionInfo() != "" {
				var err error
				lastAckedVersion, err = strconv.ParseUint(req.VersionInfo, 10, 64)
				if err != nil {
					requestLog.Error("invalid version info in xDS request, not a uint64")
					return ErrInvalidVersionInfo
				}
			}
			// lastReceivedVersion is the last version the client has seen from us;
			// it may be ACKed of NACKed.
			var lastReceivedVersion uint64
			if req.GetResponseNonce() != "" {
				var err error
				lastReceivedVersion, err = strconv.ParseUint(req.ResponseNonce, 10, 64)
				if err != nil {
					requestLog.Error("invalid response nonce info in xDS request, not a uint64")
					return ErrInvalidResponseNonce
				}
			}
			var detail string
			status := req.GetErrorDetail()
			if status != nil {
				detail = status.Message
			}

			typeURL := req.GetTypeUrl()
			if defaultTypeURL == AnyTypeURL && typeURL == "" {
				requestLog.Error("no type URL given in ADS request")
				return ErrNoADSTypeURL
			}

			if defaultTypeURL != AnyTypeURL && typeURL != defaultTypeURL {
				requestLog.Error("mismatching type URL given in xDS request")
				return ErrMismatchingTypeURL
			}

			index, exists := typeIndexes[typeURL]
			if !exists {
				requestLog.Error("unknown type URL in xDS request")
				return ErrUnknownTypeURL
			}

			state := &typeStates[index]
			source := s.sources[typeURL]

			if lastReceivedVersion > 0 {
				// Non-zero lastReceivedVersion indicates that we have already sent
				// a response to the client and client saw response.
				state.clientReceivedFirstResponse = true
			}

			if state.clientReceivedFirstResponse && lastAckedVersion == lastReceivedVersion {
				// Once we get the first ACK,
				// we can start using versionInfo for ACKing observers.
				state.responseAcked = true
			}

			if lastAckedVersion > 0 && firstRequest {
				requestLog.Info("xDS was restarted",
					logfields.Previous, lastAckedVersion,
				)
			}

			if lastAckedVersion > lastReceivedVersion && state.clientReceivedFirstResponse {
				requestLog.Warn("received invalid nonce in xDS request")
				return ErrInvalidResponseNonce
			}

			// We want to trigger HandleResourceVersionAck even for NACKs
			if state.clientReceivedFirstResponse {
				ackObserver := s.ackObservers[typeURL]
				if ackObserver != nil {
					requestLog.Debug("notifying observers of ACKs")
					if !state.responseAcked {
						// If we haven't received any ACK, it means that lastAppliedVersion
						// is stale and we can't ACK anything.
						// Also we can't send lastAppliedVersion as it would incorrectly be cached
						// as last acked version.
						ackObserver.HandleResourceVersionAck(0, lastReceivedVersion, nodeIP, state.resourceNames, typeURL, detail)
					} else {
						ackObserver.HandleResourceVersionAck(lastAckedVersion, lastReceivedVersion, nodeIP, state.resourceNames, typeURL, detail)
					}
				} else {
					requestLog.Info("ACK received but no observers are waiting for ACKs")
				}
			}

			if lastAckedVersion < lastReceivedVersion && state.clientReceivedFirstResponse {
				s.metrics.IncreaseNACK(typeURL)
				// versions after lastAppliedVersion, upto and including lastReceivedVersion are NACKed
				requestLog.Warn(
					"NACK received for versions between the reported version up to the response nonce; waiting for a version update before sending again",
					logfields.XDSDetail, detail,
				)
			}

			if state.pendingWatchCancel != nil {
				requestLog.Debug("canceling pending watch before processing request")
				state.cancelPendingWatch()
				selectCases[index].Chan = quietChValue
			}

			interestExpanded := state.updateRequestedResources(req.GetResourceNames())

			respCh := make(chan *VersionedResources, 1)
			selectCases[index].Chan = reflect.ValueOf(respCh)

			ctx, cancel := context.WithCancel(ctx)
			state.pendingWatchCancel = cancel
			watchDone := make(chan struct{})
			state.pendingWatchDone = watchDone

			requestLog.Debug(
				"starting watch resources",
				logfields.Resources, len(state.requestedResourceNames),
			)
			watchReq := sotwWatchRequest{
				logger:              requestLog,
				source:              source,
				typeURL:             typeURL,
				lastReceivedVersion: lastReceivedVersion,
				lastAckedVersion:    lastAckedVersion,
				resourceNames:       state.requestedResourceNames,
				interestExpanded:    interestExpanded,
			}
			go func() {
				defer close(watchDone)
				watchReq.WatchResources(ctx, respCh)
			}()
			firstRequest = false

		default: // Pending watch response.
			state := &typeStates[chosen]
			state.cancelPendingWatch()

			if !recvOK {
				// chosen channel was closed. If context has an error (e.g.,
				// cancelled or deadline exceeded) we should not log an error here.
				if ctx.Err() != nil {
					// The context is done, so the doneChIndex case WILL fire,
					// can just continue here
					continue
				}

				scopedLogger.Error(
					"xDS resource watch failed; terminating",
					logfields.XDSTypeURL, state.typeURL,
				)
				return ErrResourceWatch
			}

			// Disabling reading from the channel after reading any from it,
			// since the watcher will close it anyway.
			selectCases[chosen].Chan = quietChValue

			resp := recv.Interface().(*VersionedResources)

			responseLog := scopedLogger.With(
				logfields.XDSCachedVersion, resp.Version,
				logfields.XDSCanary, resp.Canary,
				logfields.XDSTypeURL, state.typeURL,
				logfields.XDSNonce, resp.Version,
			)

			resources := make([]*anypb.Any, len(resp.VersionedResources))

			// Marshall the resources into protobuf's Any type.
			for i := range resp.VersionedResources {
				any, err := anypb.New(resp.VersionedResources[i].Resource)
				if err != nil {
					responseLog.Error(
						"error marshalling xDS response with resources",
						logfields.Error, err,
						logfields.Resources, len(resp.VersionedResources),
					)
					return err
				}
				resources[i] = any
			}

			responseLog.Debug(
				"sending xDS response with resources",
				logfields.Resources, len(resp.VersionedResources),
			)

			versionStr := strconv.FormatUint(resp.Version, 10)
			out := &envoy_service_discovery.DiscoveryResponse{
				VersionInfo: versionStr,
				Resources:   resources,
				Canary:      resp.Canary,
				TypeUrl:     state.typeURL,
				Nonce:       versionStr,
			}
			err := stream.Send(out)
			if err != nil {
				return err
			}

			names := make([]string, 0, len(resp.VersionedResources))
			for _, vr := range resp.VersionedResources {
				names = append(names, vr.Name)
			}
			slices.Sort(names)
			state.resourceNames = names
		}
	}
}

// HandleDeltaRequestStream receives and processes the requests from an Delta xDS stream.
func (s *Server) HandleDeltaRequestStream(ctx context.Context, stream DeltaStream, defaultTypeURL, afterTypeURL string) error {
	// increment stream count
	streamID := s.lastStreamID.Add(1)

	reqStreamLog := s.logger.With(logfields.XDSStreamID, streamID)

	reqCh := make(chan *envoy_service_discovery.DeltaDiscoveryRequest)

	stopRecv := make(chan struct{})
	defer close(stopRecv)

	nodeId := ""

	go func(streamLog *slog.Logger) {
		defer close(reqCh)
		for {
			req, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					streamLog.Debug("Delta xDS stream closed")
				} else if strings.HasPrefix(err.Error(), grpcCanceled) {
					streamLog.Debug("Delta xDS stream canceled", logfields.Error, err)
				} else {
					streamLog.Error("error while receiving request from Delta xDS stream", logfields.Error, err)
				}
				return
			}
			if req == nil {
				streamLog.Error("received nil request from Delta xDS stream; stopping xDS stream handling")
				return
			}
			if req.GetTypeUrl() == "" {
				req.TypeUrl = defaultTypeURL
			}
			if nodeId == "" {
				nodeId = req.GetNode().GetId()
				streamLog = streamLog.With(logfields.XDSClientNode, nodeId)
			}
			streamLog.Debug("received request from Delta xDS stream", getDeltaRequestFields(req)...)

			select {
			case <-stopRecv:
				streamLog.Debug("stopping Delta xDS stream handling")
				return
			case reqCh <- req:
			}
		}
	}(reqStreamLog)

	return s.processDeltaRequestStream(ctx, reqStreamLog, stream, reqCh, defaultTypeURL, afterTypeURL)
}

func getDeltaRequestFields(req *envoy_service_discovery.DeltaDiscoveryRequest) []any {
	return []any{
		logfields.Version, req.GetInitialResourceVersions(),
		logfields.XDSTypeURL, req.GetTypeUrl(),
		logfields.XDSNonce, req.GetResponseNonce(),
	}
}

// perDeltaTypeStreamState is the state maintained per resource type for each
// delta xDS stream.
type perDeltaTypeStreamState struct {
	perTypeStreamState

	// Last ACKed version is the largest version number of any resource sent to the client
	// (== the overall cache version).
	lastAckedVersion uint64

	// ackedResourceNames is the set of resource names currently in use at the client.
	// A pending watch may hold a read-only reference to this set, so this
	// must not be mutated until the pending watch has finished.
	ackedResourceNames set.Set[string]

	// subscriptions is the set of resource names the client has expressed
	// interest in. By server convention an empty set is treated as wildcard
	// interest, and "*" is an explicit wildcard marker that may coexist with
	// named subscriptions.
	// A pending watch may hold a read-only reference to this set, so this
	// must not be mutated until the pending watch has finished.
	subscriptions set.Set[string]

	// Nonce sent in the last response, if any.
	// Non-empty means this exact response is still awaiting ACK/NACK.
	nonce string

	// pendingResponse is the last response sent for this resource type.
	pendingResponse *VersionedResources

	// deferredImmediate records that a nonce-less request updated subscriptions
	// while a previous response for this type was still awaiting ACK/NACK.
	deferredImmediate bool

	// deferredForceResponseNames tracks newly subscribed resources received
	// while a previous response for this type was still awaiting ACK/NACK.
	// These names must be force-sent in the first response after that
	// outstanding response is ACKed or NACKed.
	deferredForceResponseNames set.Set[string]
}

// processDeltaRequestStream processes the requests in an xDS stream from a channel.
func (s *Server) processDeltaRequestStream(ctx context.Context, streamLog *slog.Logger, stream DeltaStream,
	reqCh <-chan *envoy_service_discovery.DeltaDiscoveryRequest, defaultTypeURL, afterTypeURL string,
) error {
	// The request state for every type URL.
	typeStates := make([]perDeltaTypeStreamState, len(s.sources))
	defer func() {
		for i := range typeStates {
			typeStates[i].cancelPendingWatch()
		}
	}()

	// A map of a resource type's URL to the corresponding index in typeStates
	// for the resource type.
	typeIndexes := make(map[string]int, len(typeStates))

	// The set of channels to select from. Since the set of channels is
	// dynamic, we use reflection for selection.
	// The indexes in selectCases from 0 to len(typeStates)-1 match the indexes
	// in typeStates.
	selectCases := make([]reflect.SelectCase, len(typeStates)+2)

	// The last select case index is always the request channel.
	reqChIndex := len(selectCases) - 1
	selectCases[reqChIndex] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(reqCh),
	}

	// The next-to-last select case is the context's Done channel.
	doneChIndex := reqChIndex - 1
	selectCases[doneChIndex] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	}

	// Initially there are no pending watches, so just select a dead channel
	// that will never be selected.
	quietCh := make(chan *VersionedResources)
	defer close(quietCh)
	quietChValue := reflect.ValueOf(quietCh)

	i := 0
	for typeURL := range s.sources {
		typeStates[i] = perDeltaTypeStreamState{
			perTypeStreamState: perTypeStreamState{
				typeURL: typeURL,
			},
		}

		selectCases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: quietChValue,
		}

		typeIndexes[typeURL] = i

		i++
	}

	streamLog.Info("starting Delta xDS stream processing", logfields.XDSTypeURL, defaultTypeURL)

	// stream-scoped state
	nodeIP := ""
	firstRequest := true
	scopedLogger := streamLog
	for {
		// Process either a new request from the xDS stream or a response
		// from the resource watcher.
		chosen, recv, recvOK := reflect.Select(selectCases)

		switch chosen {
		case doneChIndex: // Context got canceled, most likely by the client terminating.
			scopedLogger.Debug("Delta xDS stream context canceled", logfields.Error, ctx.Err())
			return nil

		case reqChIndex: // Request received from the stream.
			if !recvOK {
				scopedLogger.Info("Delta xDS stream closed")
				return nil
			}

			req := recv.Interface().(*envoy_service_discovery.DeltaDiscoveryRequest)

			// only require Node to exist in the first request
			if firstRequest {
				id := req.GetNode().GetId()
				scopedLogger = streamLog.With(logfields.XDSClientNode, id)
				var err error
				nodeIP, err = EnvoyNodeIdToIP(id)
				if err != nil {
					scopedLogger.Error("invalid Node in Delta xDS request", logfields.Error, err)
					return ErrInvalidNodeFormat
				}
				scopedLogger.Info("Received first request in a new Delta xDS stream", getDeltaRequestFields(req)...)

				// delay responding to the first request until 'afterTypeURL' has
				// been acked, if any
				if afterTypeURL != "" {
					s.ackObservers[afterTypeURL].WaitForFirstAck(ctx, nodeIP, afterTypeURL)
				}
			}

			requestLog := scopedLogger.With(getDeltaRequestFields(req)...)

			typeURL := req.GetTypeUrl()
			if defaultTypeURL == AnyTypeURL && typeURL == "" {
				requestLog.Error("no type URL given in ADS request")
				return ErrNoADSTypeURL
			}

			if defaultTypeURL != AnyTypeURL && typeURL != defaultTypeURL {
				requestLog.Error("mismatching type URL given in xDS request",
					logfields.Expected, defaultTypeURL,
				)
				return ErrMismatchingTypeURL
			}

			index, exists := typeIndexes[typeURL]
			if !exists {
				requestLog.Error("unknown type URL in xDS request")
				return ErrUnknownTypeURL
			}
			state := &typeStates[index]

			initialRequestForType := state.pendingResponse == nil && state.nonce == "" && state.pendingWatchCancel == nil
			if state.pendingWatchCancel != nil {
				requestLog.Debug("canceling pending watch before processing request")
				state.cancelPendingWatch()
				selectCases[index].Chan = quietChValue
			}

			responseNonce := req.GetResponseNonce()
			errorDetail := req.GetErrorDetail()
			detail := ""
			if errorDetail != nil {
				detail = errorDetail.Message // can be empty
			}

			var lastReceivedVersion uint64
			var ackedResponse *VersionedResources

			if responseNonce == "" {
				if errorDetail != nil {
					requestLog.Warn("delta xDS request carries error detail without a response nonce")
					return ErrInvalidResponseNonce
				}

				// The version values in initial_resource_versions are ignored on
				// purpose. Cilium does not preserve meaningful version continuity
				// across agent restarts, so a new stream should receive all the
				// currently subscribed resources. We do, however, treat the names
				// as the client's currently installed resources so the first
				// response on a restarted stream can explicitly remove stale
				// entries that no longer exist.
				if initialRequestForType {
					for name := range req.GetInitialResourceVersions() {
						state.ackedResourceNames.Insert(name)
					}
				}
			} else { // has responseNonce
				if state.nonce == "" {
					requestLog.Warn("delta xDS request carries a response nonce but no response is awaiting ACK/NACK",
						logfields.ResponseNonce, responseNonce,
					)
					return ErrInvalidResponseNonce
				}
				if responseNonce != state.nonce {
					requestLog.Warn("invalid response nonce in delta xDS request",
						logfields.ResponseNonce, responseNonce,
						logfields.Expected, state.nonce,
					)
					return ErrInvalidResponseNonce
				}

				ackedResponse = state.pendingResponse
				if ackedResponse == nil {
					requestLog.Error("delta xDS stream state missing pending response for outstanding nonce",
						logfields.ResponseNonce, responseNonce,
					)
					return ErrInvalidResponseNonce
				}
				lastReceivedVersion = ackedResponse.Version

				if errorDetail == nil {
					state.lastAckedVersion = lastReceivedVersion
					for _, name := range ackedResponse.RemovedNames {
						state.ackedResourceNames.Remove(name)
					}
					for _, vr := range ackedResponse.VersionedResources {
						state.ackedResourceNames.Insert(vr.Name)
					}
				}

				// response is now accepted, a new request may be sent
				state.nonce = ""

				ackObserver := s.ackObservers[typeURL]
				if ackObserver != nil {
					requestLog.Debug("notifying observers of ACKs")
					var observerNames []string
					for i := range ackedResponse.VersionedResources {
						observerNames = append(observerNames, ackedResponse.VersionedResources[i].Name)
					}
					ackObserver.HandleResourceVersionAck(state.lastAckedVersion, lastReceivedVersion, nodeIP, observerNames, typeURL, detail)
				} else {
					requestLog.Info("ACK or NACK received but no observers are waiting for ACKs")
				}
				if errorDetail != nil && state.lastAckedVersion < lastReceivedVersion {
					s.metrics.IncreaseNACK(typeURL)
					// versions after lastAckedVersion, upto and including
					// lastReceivedVersion were NACKed
					requestLog.Warn(
						"delta xDS NACK received for versions between the reported version up to the response nonce; waiting for a version update before sending again",
						logfields.XDSDetail, detail,
					)
				}
			}

			// update subscriptions
			subscribe := req.GetResourceNamesSubscribe()
			unsubscribe := req.GetResourceNamesUnsubscribe()
			immediate := len(subscribe) > 0 || len(unsubscribe) > 0

			for _, name := range unsubscribe {
				state.subscriptions.Remove(name)
				state.deferredForceResponseNames.Remove(name)
				state.ackedResourceNames.Remove(name)
			}
			var forceResponseNames set.Set[string]
			for _, name := range subscribe {
				state.subscriptions.Insert(name)
				forceResponseNames.Insert(name)
			}

			if state.nonce != "" {
				// response is pending, defer any immediate responses
				if immediate {
					state.deferredImmediate = true
				}
				state.deferredForceResponseNames.Merge(forceResponseNames)
				firstRequest = false
				continue
			}

			// state.nonce == "" : either immediate response of a watch must be created

			source := s.sources[typeURL]

			// fold in any deferred immediate state
			immediate = immediate || state.deferredImmediate || !state.deferredForceResponseNames.Empty()
			state.deferredImmediate = false
			forceResponseNames.Merge(state.deferredForceResponseNames)
			state.deferredForceResponseNames.Clear()

			respCh := make(chan *VersionedResources, 1)
			selectCases[index].Chan = reflect.ValueOf(respCh)

			ctx, cancel := context.WithCancel(ctx)
			state.pendingWatchCancel = cancel
			watchDone := make(chan struct{})
			state.pendingWatchDone = watchDone

			requestLog.Debug(
				"starting watch resources",
				logfields.Info, immediate,
				logfields.Resources, state.subscriptions.Len(),
			)
			watchReq := deltaWatchRequest{
				logger:              requestLog,
				source:              source,
				typeURL:             typeURL,
				lastReceivedVersion: lastReceivedVersion,
				lastAckedVersion:    state.lastAckedVersion,
				subscriptions:       state.subscriptions,
				ackedResourceNames:  state.ackedResourceNames,
				forceResponseNames:  forceResponseNames,
				immediate:           immediate,
				forceEmptyResponse:  initialRequestForType,
			}
			go func() {
				defer close(watchDone)
				watchReq.WatchResources(ctx, respCh)
			}()
			firstRequest = false

		default: // Pending watch response.
			state := &typeStates[chosen]
			state.cancelPendingWatch()

			if !recvOK {
				// chosen channel was closed. If context has an error (e.g.,
				// cancelled or deadline exceeded) we should not log an error here.
				if ctx.Err() != nil {
					// The context is done, so the doneChIndex case WILL fire,
					// can just continue here
					continue
				}

				scopedLogger.Error(
					"xDS resource watch failed; terminating",
					logfields.XDSTypeURL, state.typeURL,
				)
				return ErrResourceWatch
			}

			// Disabling reading from the channel after reading any from it,
			// since the watcher will close it anyway.
			selectCases[chosen].Chan = quietChValue

			resp := recv.Interface().(*VersionedResources)

			responseLog := scopedLogger.With(
				logfields.XDSCachedVersion, resp.Version,
				logfields.XDSCanary, resp.Canary,
				logfields.XDSTypeURL, state.typeURL,
				logfields.XDSNonce, resp.Version,
			)

			resources := make([]*envoy_service_discovery.Resource, len(resp.VersionedResources))

			// Marshall the resources into protobuf's Any type.
			for i := range resp.VersionedResources {
				any, err := anypb.New(resp.VersionedResources[i].Resource)
				if err != nil {
					responseLog.Error(
						"error marshalling xDS response with resources",
						logfields.Error, err,
						logfields.Resources, len(resp.VersionedResources),
					)
					return err
				}
				versionStr := strconv.FormatUint(resp.VersionedResources[i].Version, 10)

				resources[i] = &envoy_service_discovery.Resource{
					Name:     resp.VersionedResources[i].Name,
					Version:  versionStr,
					Resource: any,
				}
			}

			responseLog.Debug(
				"sending xDS response with resources",
				logfields.Resources, len(resources),
			)

			versionStr := strconv.FormatUint(resp.Version, 10)
			out := &envoy_service_discovery.DeltaDiscoveryResponse{
				TypeUrl:           state.typeURL,
				Resources:         resources,
				RemovedResources:  resp.RemovedNames,
				Nonce:             versionStr,
				SystemVersionInfo: versionStr,
			}
			err := stream.Send(out)
			if err != nil {
				return err
			}

			state.nonce = versionStr
			state.pendingResponse = resp
		}
	}
}
