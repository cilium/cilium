// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"

	envoy_api_v2 "github.com/cilium/proxy/go/envoy/api/v2"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
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
	// watchers maps each supported type URL to its corresponding resource
	// watcher.
	watchers map[string]*ResourceWatcher

	// ackObservers maps each supported type URL to its corresponding observer
	// of ACKs received from Envoy nodes.
	ackObservers map[string]ResourceVersionAckObserver

	// lastStreamID is the identifier of the last processed stream.
	// It is incremented atomically when starting the handling of a new stream.
	lastStreamID uint64
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
func NewServer(resourceTypes map[string]*ResourceTypeConfiguration,
	resourceAccessTimeout time.Duration) *Server {
	watchers := make(map[string]*ResourceWatcher, len(resourceTypes))
	ackObservers := make(map[string]ResourceVersionAckObserver, len(resourceTypes))
	for typeURL, resType := range resourceTypes {
		w := NewResourceWatcher(typeURL, resType.Source, resourceAccessTimeout)
		resType.Source.AddResourceVersionObserver(w)
		watchers[typeURL] = w

		if resType.AckObserver != nil {
			ackObservers[typeURL] = resType.AckObserver
		}
	}

	// TODO: Unregister the watchers when stopping the server.

	return &Server{watchers: watchers, ackObservers: ackObservers}
}

func getXDSRequestFields(req *envoy_api_v2.DiscoveryRequest) logrus.Fields {
	return logrus.Fields{
		logfields.XDSAckedVersion: req.GetVersionInfo(),
		logfields.XDSClientNode:   req.GetNode().GetId(),
		logfields.XDSTypeURL:      req.GetTypeUrl(),
		logfields.XDSNonce:        req.GetResponseNonce(),
	}
}

// HandleRequestStream receives and processes the requests from an xDS stream.
func (s *Server) HandleRequestStream(ctx context.Context, stream Stream, defaultTypeURL string) error {
	// increment stream count
	streamID := atomic.AddUint64(&s.lastStreamID, 1)

	streamLog := log.WithField(logfields.XDSStreamID, streamID)

	reqCh := make(chan *envoy_api_v2.DiscoveryRequest)

	stopRecv := make(chan struct{})
	defer close(stopRecv)

	go func() {
		defer close(reqCh)
		for {
			req, err := stream.Recv()
			if err != nil {
				if err == io.EOF {
					streamLog.Debug("xDS stream closed")
				} else if strings.HasPrefix(err.Error(), grpcCanceled) {
					streamLog.WithError(err).Debug("xDS stream canceled")
				} else {
					streamLog.WithError(err).Error("error while receiving request from xDS stream")
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
			streamLog.WithFields(getXDSRequestFields(req)).Debug("received request from xDS stream")
			select {
			case <-stopRecv:
				streamLog.Debug("stopping xDS stream handling")
				return
			case reqCh <- req:
			}
		}
	}()

	return s.processRequestStream(ctx, streamLog, stream, reqCh, defaultTypeURL)
}

// perTypeStreamState is the state maintained per resource type for each
// xDS stream.
type perTypeStreamState struct {
	// typeURL identifies the resource type.
	typeURL string

	// pendingWatchCancel is a pending watch on this resource type.
	// If nil, no watch is pending.
	pendingWatchCancel context.CancelFunc

	// version is the last version sent. This is needed so that we'll know
	// if a new request is an ACK (VersionInfo matches current version), or a NACK
	// (VersionInfo matches an earlier version).
	version uint64

	// resourceNames is the list of names of resources sent in the last
	// response to a request for this resource type.
	resourceNames []string
}

// processRequestStream processes the requests in an xDS stream from a channel.
func (s *Server) processRequestStream(ctx context.Context, streamLog *logrus.Entry, stream Stream,
	reqCh <-chan *envoy_api_v2.DiscoveryRequest, defaultTypeURL string) error {
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

	for {
		// Process either a new request from the xDS stream or a response
		// from the resource watcher.
		chosen, recv, recvOK := reflect.Select(selectCases)

		switch chosen {
		case doneChIndex: // Context got canceled, most likely by the client terminating.
			streamLog.WithError(ctx.Err()).Debug("xDS stream context canceled")
			return ctx.Err()

		case reqChIndex: // Request received from the stream.
			if !recvOK {
				streamLog.Info("xDS stream closed")
				return nil
			}

			req := recv.Interface().(*envoy_api_v2.DiscoveryRequest)

			requestLog := streamLog.WithFields(getXDSRequestFields(req))

			// Ensure that the version info is a string that was sent by this
			// server or the empty string (the first request in a stream should
			// always have an empty version info).
			var versionInfo uint64
			if req.GetVersionInfo() != "" {
				var err error
				versionInfo, err = strconv.ParseUint(req.VersionInfo, 10, 64)
				if err != nil {
					requestLog.Errorf("invalid version info in xDS request, not a uint64")
					return ErrInvalidVersionInfo
				}
			}
			var nonce uint64
			if req.GetResponseNonce() != "" {
				var err error
				nonce, err = strconv.ParseUint(req.ResponseNonce, 10, 64)
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

			nodeIP, err := IstioNodeToIP(req.GetNode())
			if err != nil {
				requestLog.WithError(err).Error("invalid Node in xDS request")
				return ErrInvalidNodeFormat
			}

			// Response nonce is always the same as the response version.
			// Request version indicates the last acked version. If the
			// response nonce in the request is different (smaller) than
			// the version, all versions upto that version are acked, but
			// the versions from that to and including the nonce are nacked.
			if versionInfo <= nonce {
				ackObserver := s.ackObservers[typeURL]
				if ackObserver != nil {
					requestLog.Debug("notifying observers of ACKs")
					ackObserver.HandleResourceVersionAck(versionInfo, nonce, nodeIP, state.resourceNames, typeURL, detail)
				} else {
					requestLog.Debug("ACK received but no observers are waiting for ACKs")
				}
				if versionInfo < nonce {
					// versions after VersionInfo, upto and including ResponseNonce are NACKed
					requestLog.WithField(logfields.XDSDetail, detail).Warningf("NACK received for versions after %s and up to %s; waiting for a version update before sending again", req.VersionInfo, req.ResponseNonce)
					// Watcher will behave as if the sent version was acked.
					// Otherwise we will just be sending the same failing
					// version over and over filling logs.
					versionInfo = state.version
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

				requestLog.Debugf("starting watch on %d resources", len(req.GetResourceNames()))
				go watcher.WatchResources(ctx, typeURL, versionInfo, nodeIP, req.GetResourceNames(), respCh)
			} else {
				requestLog.Debug("received invalid nonce in xDS request; ignoring request")
			}
		default: // Pending watch response.
			state := &typeStates[chosen]
			state.pendingWatchCancel()
			state.pendingWatchCancel = nil

			if !recvOK {
				streamLog.WithField(logfields.XDSTypeURL, state.typeURL).
					Error("xDS resource watch failed; terminating")
				return ErrResourceWatch
			}

			// Disabling reading from the channel after reading any from it,
			// since the watcher will close it anyway.
			selectCases[chosen].Chan = quietChValue

			resp := recv.Interface().(*VersionedResources)

			responseLog := streamLog.WithFields(logrus.Fields{
				logfields.XDSCachedVersion: resp.Version,
				logfields.XDSCanary:        resp.Canary,
				logfields.XDSTypeURL:       state.typeURL,
				logfields.XDSNonce:         resp.Version,
			})

			resources := make([]*any.Any, len(resp.Resources))

			// Marshall the resources into protobuf's Any type.
			for i, res := range resp.Resources {
				data, err := proto.Marshal(res)
				if err != nil {
					responseLog.WithError(err).Errorf("error marshalling xDS response (%d resources)", len(resp.Resources))
					return err
				}
				resources[i] = &any.Any{
					TypeUrl: state.typeURL,
					Value:   data,
				}
			}

			responseLog.Debugf("sending xDS response with %d resources", len(resp.Resources))

			versionStr := strconv.FormatUint(resp.Version, 10)
			out := &envoy_api_v2.DiscoveryResponse{
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

			state.version = resp.Version
			state.resourceNames = resp.ResourceNames
		}
	}
}
