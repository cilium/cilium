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
	"io"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/sirupsen/logrus"
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

	// ErrResourceWatch is the error returned whenever an internal error
	// occurs while waiting for new versions of resources.
	ErrResourceWatch = errors.New("resource watch failed")
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

		ackObservers[typeURL] = resType.AckObserver
	}

	// TODO: Unregister the watchers when stopping the server.

	return &Server{watchers: watchers, ackObservers: ackObservers}
}

func getXDSRequestFields(req *envoy_api_v2.DiscoveryRequest) logrus.Fields {
	return logrus.Fields{
		logfields.XDSVersionInfo: req.GetVersionInfo(),
		logfields.XDSClientNode:  req.GetNode(),
		logfields.XDSTypeURL:     req.GetTypeUrl(),
		logfields.XDSNonce:       req.GetResponseNonce(),
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

	// nonce is the nonce sent in the last response to a request for this
	// resource type.
	nonce string

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

	// The last nonce returned in a response in this stream.
	var responseNonce uint64

	for {
		// Process either a new request from the xDS stream or a response
		// from the resource watcher.
		chosen, recv, recvOK := reflect.Select(selectCases)

		switch chosen {
		case doneChIndex: // Context got canceled.
			streamLog.WithError(ctx.Err()).Error("xDS stream context canceled")
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
			var versionInfo *uint64
			if req.GetVersionInfo() != "" {
				versionInfoVal, err := strconv.ParseUint(req.VersionInfo, 10, 64)
				if err != nil {
					requestLog.Errorf("invalid version info in xDS request, not a uint64")
					return ErrInvalidVersionInfo
				}
				versionInfo = &versionInfoVal
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

			// Only handle a request if the nonce is valid, i.e. if it's
			// the first request (which nonce is "") or if it's the nonce of
			// the last response that was sent.
			//
			// If the nonce is different (stale), the client hasn't processed
			// the last response yet. Ignore every request until it processes
			// that response and sends a request with that response's nonce.
			if state.nonce == "" || state.nonce == req.GetResponseNonce() {
				if state.pendingWatchCancel != nil {
					// A pending watch exists for this type URL. Cancel it to
					// start a new watch.
					requestLog.Debug("canceling pending watch")
					state.pendingWatchCancel()
				} else if versionInfo != nil {
					// If no pending watch exists, then this request is an ACK
					// for the last response for this resource type.
					// Notify every observer of the ACK.
					requestLog.Debug("notifying observers of ACK")
					s.ackObservers[typeURL].HandleResourceVersionAck(*versionInfo, req.GetNode(), state.resourceNames, typeURL)
				}

				respCh := make(chan *VersionedResources, 1)
				selectCases[index].Chan = reflect.ValueOf(respCh)

				ctx, cancel := context.WithCancel(ctx)
				state.pendingWatchCancel = cancel

				requestLog.Debugf("starting watch on %d resources", len(req.GetResourceNames()))
				go s.watchers[typeURL].WatchResources(ctx, typeURL, versionInfo,
					req.GetNode(), req.GetResourceNames(), respCh)
			} else {
				requestLog.Debug("received stale nonce in xDS request; ignoring request")
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

			responseNonce++
			nonce := strconv.FormatUint(responseNonce, 10)

			responseLog := streamLog.WithFields(logrus.Fields{
				logfields.XDSVersionInfo: resp.Version,
				logfields.XDSCanary:      resp.Canary,
				logfields.XDSTypeURL:     state.typeURL,
				logfields.XDSNonce:       nonce,
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

			responseLog.Infof("sending xDS response with %d resources", len(resp.Resources))

			out := &envoy_api_v2.DiscoveryResponse{
				VersionInfo: strconv.FormatUint(resp.Version, 10),
				Resources:   resources,
				Canary:      resp.Canary,
				TypeUrl:     state.typeURL,
				Nonce:       nonce,
			}
			err := stream.Send(out)
			if err != nil {
				return err
			}

			state.nonce = nonce
			state.resourceNames = resp.ResourceNames
		}
	}
}
