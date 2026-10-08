package delta

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/log"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/config"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
)

// Server is a wrapper interface which is meant to hold the proper stream handler for each xDS protocol.
type Server interface {
	DeltaStreamHandler(stream stream.DeltaStream, typeURL string) error
}

type Callbacks interface {
	// OnDeltaStreamOpen is called once an incremental xDS stream is open with a stream ID and the type URL (or "" for ADS).
	// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
	OnDeltaStreamOpen(context.Context, int64, string) error
	// OnDeltaStreamClosed is called immediately prior to closing an xDS stream with a stream ID.
	OnDeltaStreamClosed(int64, *core.Node)
	// OnStreamDeltaRequest is called once a request is received on a stream.
	// Returning an error will end processing and close the stream. OnStreamClosed will still be called.
	OnStreamDeltaRequest(int64, *discovery.DeltaDiscoveryRequest) error
	// OnStreamDeltaResponse is called immediately prior to sending a response on a stream.
	OnStreamDeltaResponse(int64, *discovery.DeltaDiscoveryRequest, *discovery.DeltaDiscoveryResponse)
}

var deltaErrorResponse = &cache.RawDeltaResponse{}

type server struct {
	cache     cache.ConfigWatcher
	callbacks Callbacks

	// total stream count for counting bi-di streams
	streamCount int64
	ctx         context.Context

	// Local configuration flags for individual xDS implementations.
	opts config.Opts
}

// WithLogger configures the server logger. Defaults to no logging
func WithLogger(logger log.Logger) config.XDSOption {
	return func(o *config.Opts) {
		o.Logger = logger
	}
}

// DeactivateLegacyWildcard deactivates legacy wildcard mode for all resource types.
// In legacy wildcard mode, empty requests to a stream, are treated as wildcard requests as long
// as there is no request made with resources or explicit wildcard requests on the same stream.
// When deactivated, empty requests are treated as a request with no subscriptions to any resource.
// This is recommended for when you are using the go-control-plane to serve grpc-xds clients.
// These clients never want to treat an empty request as a wildcard subscription.
func DeactivateLegacyWildcard() config.XDSOption {
	return config.DeactivateLegacyWildcard()
}

// DeactivateLegacyWildcardForTypes deactivates legacy wildcard mode for specific resource types.
// In legacy wildcard mode, empty requests to a stream, are treated as wildcard requests as long
// as there is no request made with resources or explicit wildcard requests on the same stream.
// When deactivated, empty requests are treated as a request with no subscriptions to any resource.
func DeactivateLegacyWildcardForTypes(types []string) config.XDSOption {
	return config.DeactivateLegacyWildcardForTypes(types)
}

// NewServer creates a delta xDS specific server which utilizes a ConfigWatcher and delta Callbacks.
func NewServer(ctx context.Context, config cache.ConfigWatcher, callbacks Callbacks, opts ...config.XDSOption) Server {
	s := &server{
		cache:     config,
		callbacks: callbacks,
		ctx:       ctx,
	}

	// Parse through our options
	for _, opt := range opts {
		opt(&s.opts)
	}

	return s
}

func (s *server) processDelta(str stream.DeltaStream, reqCh <-chan *discovery.DeltaDiscoveryRequest, defaultTypeURL string) error {
	streamID := atomic.AddInt64(&s.streamCount, 1)

	// streamNonce holds a unique nonce for req-resp pairs per xDS stream.
	var streamNonce int64

	// a collection of stack allocated watches per request type
	watches := newWatches()

	node := &core.Node{}

	defer func() {
		watches.Cancel()
		if s.callbacks != nil {
			s.callbacks.OnDeltaStreamClosed(streamID, node)
		}
	}()

	// sends a response, returns the new stream nonce
	send := func(resp cache.DeltaResponse) (string, error) {
		if resp == nil {
			return "", errors.New("missing response")
		}

		response, err := resp.GetDeltaDiscoveryResponse()
		if err != nil {
			return "", err
		}

		streamNonce++
		response.Nonce = strconv.FormatInt(streamNonce, 10)
		if s.callbacks != nil {
			s.callbacks.OnStreamDeltaResponse(streamID, resp.GetDeltaRequest(), response)
		}

		return response.GetNonce(), str.Send(response)
	}

	// process a single delta response
	process := func(resp cache.DeltaResponse) error {
		typ := resp.GetDeltaRequest().GetTypeUrl()
		if resp == deltaErrorResponse {
			return status.Errorf(codes.Unavailable, "%s watch failed", typ)
		}

		nonce, err := send(resp)
		if err != nil {
			return err
		}

		watch := watches.deltaWatches[typ]
		watch.nonce = nonce

		watch.subscription.SetReturnedResources(resp.GetNextVersionMap())
		watches.deltaWatches[typ] = watch
		return nil
	}

	// processAll purges the deltaMuxedResponses channel
	processAll := func() error {
		for {
			select {
			// We watch the multiplexed channel for incoming responses.
			case resp, more := <-watches.deltaMuxedResponses:
				if !more {
					break
				}
				if err := process(resp); err != nil {
					return err
				}
			default:
				return nil
			}
		}
	}

	if s.callbacks != nil {
		if err := s.callbacks.OnDeltaStreamOpen(str.Context(), streamID, defaultTypeURL); err != nil {
			return err
		}
	}

	for {
		select {
		case <-s.ctx.Done():
			return nil
		// We watch the multiplexed channel for incoming responses.
		case resp, more := <-watches.deltaMuxedResponses:
			// input stream ended or errored out
			if !more {
				break
			}

			if err := process(resp); err != nil {
				return err
			}
		case req, more := <-reqCh:
			// input stream ended or errored out
			if !more {
				return nil
			}

			if req == nil {
				return status.Errorf(codes.Unavailable, "empty request")
			}

			// make sure all existing responses are processed prior to new requests to avoid deadlock
			if err := processAll(); err != nil {
				return err
			}

			if s.callbacks != nil {
				if err := s.callbacks.OnStreamDeltaRequest(streamID, req); err != nil {
					return err
				}
			}

			// The node information might only be set on the first incoming delta discovery request, so store it here so we can
			// reset it on subsequent requests that omit it.
			if req.GetNode() != nil {
				node = req.GetNode()
			} else {
				req.Node = node
			}

			// type URL is required for ADS but is implicit for any other xDS stream
			if defaultTypeURL == resource.AnyType {
				if req.GetTypeUrl() == "" {
					return status.Errorf(codes.InvalidArgument, "type URL is required for ADS")
				}
			} else if req.GetTypeUrl() == "" {
				req.TypeUrl = defaultTypeURL
			}

			typeURL := req.GetTypeUrl()

			// cancel existing watch to (re-)request a newer version
			watch, ok := watches.deltaWatches[typeURL]
			if !ok {
				// Initialize the state of the type subscription.
				// Since there was no previous subscription, we know we're handling the first request of this type
				// so we set the initial resource versions if we have any.
				// We also set the subscription as wildcard based on its legacy meaning (no resource name sent in resource_names_subscribe).
				// If the subscription starts with this legacy mode, adding new resources will not unsubscribe from wildcard.
				// It can still be done by explicitly unsubscribing from "*"
				watch.subscription = stream.NewDeltaSubscription(req.GetResourceNamesSubscribe(), req.GetResourceNamesUnsubscribe(), req.GetInitialResourceVersions(), s.opts.IsLegacyWildcardActive(typeURL))
			} else {
				watch.Cancel()

				// Update subscription with the new requests
				watch.subscription.UpdateResourceSubscriptions(
					req.GetResourceNamesSubscribe(),
					req.GetResourceNamesUnsubscribe(),
				)
			}

			var err error
			watch.cancel, err = s.cache.CreateDeltaWatch(req, watch.subscription, watches.deltaMuxedResponses)
			if err != nil {
				return err
			}
			watches.deltaWatches[typeURL] = watch
		}
	}
}

func (s *server) DeltaStreamHandler(str stream.DeltaStream, typeURL string) error {
	// a channel for receiving incoming delta requests
	reqCh := make(chan *discovery.DeltaDiscoveryRequest)

	// we need to concurrently handle incoming requests since we kick off processDelta as a return
	go func() {
		defer close(reqCh)
		for {
			req, err := str.Recv()
			if err != nil {
				return
			}
			select {
			case reqCh <- req:
			case <-str.Context().Done():
				return
			case <-s.ctx.Done():
				return
			}
		}
	}()
	return s.processDelta(str, reqCh, typeURL)
}
