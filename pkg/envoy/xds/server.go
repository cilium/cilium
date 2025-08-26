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
	"strconv"
	"strings"
	"sync/atomic"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/anypb"

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
	// watchers maps each supported type URL to its corresponding resource
	// watcher.
	watchers map[string]*ResourceWatcher

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
	Source ObservableResourceSource

	// AckObserver is called back whenever a node acknowledges having applied a
	// version of the resources of this type.
	AckObserver ResourceVersionAckObserver
}

// NewServer creates an xDS gRPC stream handler using the given resource
// sources.
// types maps each supported resource type URL to its corresponding resource
// source and ACK observer.
func NewServer(logger *slog.Logger, resourceTypes map[string]*ResourceTypeConfiguration, restorerPromise promise.Promise[endpointstate.Restorer], metrics Metrics) *Server {
	watchers := make(map[string]*ResourceWatcher, len(resourceTypes))
	ackObservers := make(map[string]ResourceVersionAckObserver, len(resourceTypes))
	for typeURL, resType := range resourceTypes {
		w := NewResourceWatcher(logger, typeURL, resType.Source)
		resType.Source.AddResourceVersionObserver(w)
		watchers[typeURL] = w

		if resType.AckObserver != nil {
			if restorerPromise != nil {
				resType.AckObserver.MarkRestorePending()
			}
			ackObservers[typeURL] = resType.AckObserver
		}
	}

	// TODO: Unregister the watchers when stopping the server.

	return &Server{logger: logger, watchers: watchers, ackObservers: ackObservers, metrics: metrics}
}

func (s *Server) RestoreCompleted() {
	for _, ackObserver := range s.ackObservers {
		ackObserver.MarkRestoreCompleted()
	}
}

func getXDSRequestFields(req *envoy_service_discovery.DiscoveryRequest) []any {
	return []any{
		logfields.XDSAckedVersion, req.GetVersionInfo(),
		logfields.XDSTypeURL, req.GetTypeUrl(),
		logfields.XDSNonce, req.GetResponseNonce(),
	}
}

// HandleRequestStream receives and processes the requests from an xDS stream.
func (s *Server) HandleRequestStream(ctx context.Context, stream Stream, defaultTypeURL string) error {
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

	return s.processRequestStream(ctx, reqStreamLog, stream, reqCh, defaultTypeURL)
}

// perTypeStreamState is the state maintained per resource type for each
// xDS stream.
type perTypeStreamState struct {
	// typeURL identifies the resource type.
	typeURL string

	// pendingWatchCancel is a pending watch on this resource type.
	// If nil, no watch is pending.
	pendingWatchCancel context.CancelFunc

	// resourceNames is the list of names of resources sent in the last
	// response to a request for this resource type.
	resourceNames []string
}

// processRequestStream processes the requests in an xDS stream from a channel.
func (s *Server) processRequestStream(ctx context.Context, streamLog *slog.Logger, stream Stream,
	reqCh <-chan *envoy_service_discovery.DiscoveryRequest, defaultTypeURL string,
) error {
	// The request state for every type URL.
	typeStates := make([]perTypeStreamState, len(s.watchers))
	defer func() {
		for _, state := range typeStates {
			if state.pendingWatchCancel != nil {
				state.pendingWatchCancel()
			}
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
	for typeURL := range s.watchers {
		typeStates[i] = perTypeStreamState{
			typeURL: typeURL,
		}

		selectCases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: quietChValue,
		}

		typeIndexes[typeURL] = i

		i++
	}

	streamLog.Info("starting xDS stream processing")

	nodeIP := ""
	firstRequest := true
	scopedLogger := streamLog
	// Indicates if client received the first response,
	// but it doesn't necessarily mean that it was ACKed.
	clientReceivedFirstResponse := false
	// responseAcked indicates if we already
	// had some request on this stream that was ACKed by a client.
	responseAcked := false
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
			}

			requestLog := scopedLogger.With(getXDSRequestFields(req)...)

			// VersionInfo is property of resources,
			// while nonce is property of the stream.
			// VersionInfo is only empty for a new client instance that did not
			// receive any ACKed version of resources previously.
			// In case of xDS server restart (cilium-agent),
			// Envoy will send a request with VersionInfo set to the last ACKed version
			// it received. Additionally, nonce will be empty.
			var lastAppliedVersion uint64
			if req.GetVersionInfo() != "" {
				var err error
				lastAppliedVersion, err = strconv.ParseUint(req.VersionInfo, 10, 64)
				if err != nil {
					requestLog.Error("invalid version info in xDS request, not a uint64")
					return ErrInvalidVersionInfo
				}
			}
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

			index, exists := typeIndexes[typeURL]
			if !exists {
				requestLog.Error("unknown type URL in xDS request")
				return ErrUnknownTypeURL
			}

			state := &typeStates[index]
			watcher := s.watchers[typeURL]

			if lastReceivedVersion > 0 {
				// Non-zero lastReceivedVersion indicates that we have already sent
				// a response to the client and client saw response.
				clientReceivedFirstResponse = true
			}

			if clientReceivedFirstResponse && lastAppliedVersion == lastReceivedVersion {
				// Once we get the first ACK,
				// we can start using versionInfo for ACKing observers.
				responseAcked = true
			}

			if lastAppliedVersion > 0 && firstRequest {
				requestLog.Info("xDS was restarted",
					logfields.Previous, lastAppliedVersion,
				)
			}

			if lastAppliedVersion > lastReceivedVersion && clientReceivedFirstResponse {
				requestLog.Warn("received invalid nonce in xDS request")
				return ErrInvalidResponseNonce
			}

			// We want to trigger HandleResourceVersionAck even for NACKs
			if clientReceivedFirstResponse {
				ackObserver := s.ackObservers[typeURL]
				if ackObserver != nil {
					requestLog.Debug("notifying observers of ACKs")
					if !responseAcked {
						// If we haven't received any ACK, it means that lastAppliedVersion
						// is stale and we can't ACK anything.
						// Also we can't send lastAppliedVersion as it would incorrectly be cached
						// as last acked version.
						ackObserver.HandleResourceVersionAck(0, lastReceivedVersion, nodeIP, state.resourceNames, typeURL, detail)
					} else {
						ackObserver.HandleResourceVersionAck(lastAppliedVersion, lastReceivedVersion, nodeIP, state.resourceNames, typeURL, detail)
					}
				} else {
					requestLog.Info("ACK received but no observers are waiting for ACKs")
				}
			}

			if lastAppliedVersion < lastReceivedVersion && clientReceivedFirstResponse {
				s.metrics.IncreaseNACK(typeURL)
				// versions after lastAppliedVersion, upto and including lastReceivedVersion are NACKed
				requestLog.Warn(
					"NACK received for versions after %s and up to %s; waiting for a version update before sending again",
					logfields.XDSDetail, detail,
					logfields.Version, req.VersionInfo,
					logfields.ResponseNonce, req.ResponseNonce,
				)
			}

			if state.pendingWatchCancel != nil {
				// A pending watch exists for this type URL. Cancel it to
				// start a new watch.
				requestLog.Debug("canceling pending watch")
				state.pendingWatchCancel()
			}

			respCh := make(chan *VersionedResources, 1)
			selectCases[index].Chan = reflect.ValueOf(respCh)

			ctx, cancel := context.WithCancel(ctx)
			state.pendingWatchCancel = cancel

			requestLog.Debug(
				"starting watch resources",
				logfields.Resources, len(req.GetResourceNames()),
			)
			go watcher.WatchResources(ctx, typeURL, lastReceivedVersion, lastAppliedVersion, nodeIP, req.GetResourceNames(), respCh)
			firstRequest = false

		default: // Pending watch response.
			state := &typeStates[chosen]
			state.pendingWatchCancel()
			state.pendingWatchCancel = nil

			if !recvOK {
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

			resources := make([]*anypb.Any, len(resp.Resources))

			// Marshall the resources into protobuf's Any type.
			for i, res := range resp.Resources {
				any, err := anypb.New(res)
				if err != nil {
					responseLog.Error(
						"error marshalling xDS response with resources",
						logfields.Error, err,
						logfields.Resources, len(resp.Resources),
					)
					return err
				}
				resources[i] = any
			}

			responseLog.Debug(
				"sending xDS response with resources",
				logfields.Resources, len(resp.Resources),
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

			state.resourceNames = resp.ResourceNames
		}
	}
}
