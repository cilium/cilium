package sotw

import (
	"reflect"
	"sync/atomic"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
)

// process handles a bi-di stream request
func (s *server) process(str stream.Stream, reqCh chan *discovery.DiscoveryRequest, defaultTypeURL string) error {
	// create our streamWrapper which can be passed down to sub control loops.
	// this is useful for abstracting critical information for various types of
	// xDS resource processing.
	sw := streamWrapper{
		stream:    str,
		ID:        atomic.AddInt64(&s.streamCount, 1), // increment stream count
		callbacks: s.callbacks,
		node:      &core.Node{}, // node may only be set on the first discovery request

		// a collection of stack allocated watches per request type.
		watches: newWatches(),
	}

	// cleanup once our stream has ended.
	defer sw.shutdown()

	if s.callbacks != nil {
		if err := s.callbacks.OnStreamOpen(str.Context(), sw.ID, defaultTypeURL); err != nil {
			return err
		}
	}

	// type URL is required for ADS but is implicit for xDS
	if defaultTypeURL == resource.AnyType && s.opts.Ordered {
		// When using ADS we need to order responses.
		// This is guaranteed in the xDS protocol specification
		// as ADS is required to be eventually consistent.
		// More details can be found here if interested:
		// https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#eventual-consistency-considerations

		// Trigger a different code path specifically for ADS.
		// We want resource ordering so things don't get sent before they should.
		// This is a blocking call and will exit the process function
		// on successful completion.
		s.opts.Logger.Debugf("[sotw] Switching to ordered ADS implementation for stream %d", sw.ID)
		return s.processADS(&sw, reqCh)
	}

	// do an initial recompute so we can load the first 2 channels:
	// <-reqCh
	// s.ctx.Done()
	sw.watches.recompute(s.ctx, reqCh)

	for {
		// The list of select cases looks like this:
		// 0: <- ctx.Done
		// 1: <- reqCh
		// 2...: per type watches
		index, value, ok := reflect.Select(sw.watches.cases)
		switch index {
		// ctx.Done() -> if we receive a value here we return
		// as no further computation is needed
		case 0:
			return nil
		// Case 1 handles any request inbound on the stream
		// and handles all initialization as needed
		case 1:
			// input stream ended or failed
			if !ok {
				return nil
			}

			req := value.Interface().(*discovery.DiscoveryRequest)
			if req == nil {
				s.opts.Logger.Debugf("[sotw] Rejecting empty request for stream %d", sw.ID)
				return status.Errorf(codes.Unavailable, "empty request")
			}

			// Only first request is guaranteed to hold node info so if it's missing, reassign.
			if req.GetNode() != nil {
				sw.node = req.GetNode()
			} else {
				req.Node = sw.node
			}

			// type URL is required for ADS but is implicit for xDS
			switch {
			case defaultTypeURL == resource.AnyType && req.GetTypeUrl() == "":
				s.opts.Logger.Debugf("[sotw] Rejecting request as missing URL for stream %d", sw.ID)
				return status.Errorf(codes.InvalidArgument, "type URL is required for ADS")
			case req.GetTypeUrl() == "":
				req.TypeUrl = defaultTypeURL
			}

			if s.callbacks != nil {
				if err := s.callbacks.OnStreamRequest(sw.ID, req); err != nil {
					return err
				}
			}

			typeURL := req.GetTypeUrl()
			var subscription stream.Subscription
			w, ok := sw.watches.responders[typeURL]
			if ok {
				if w.nonce != "" && req.GetResponseNonce() != w.nonce {
					// The request does not match the stream nonce, ignore it as per
					// https://www.envoyproxy.io/docs/envoy/v1.28.0/api-docs/xds_protocol#resource-updates
					// Ignore this request and wait for the next one
					// This behavior is being discussed in https://github.com/envoyproxy/envoy/issues/10363
					// as it might create a race in edge cases, but it matches the current protocol definition
					s.opts.Logger.Infof("[sotw] Skipping request as nonce is stale for type %s and stream %d", typeURL, sw.ID)
					break
				}

				// We found an existing watch
				// Close it to ensure the Cache will not reply to it while we modify the subscription state
				w.close()

				subscription = w.sub
				subscription.SetResourceSubscription(req.GetResourceNames())
			} else {
				s.opts.Logger.Debugf("[sotw] New subscription for type %s and stream %d", typeURL, sw.ID)
				subscription = stream.NewSotwSubscription(req.GetResourceNames(), s.opts.IsLegacyWildcardActive(typeURL))
			}

			responder := make(chan cache.Response, 1)
			cancel, err := s.cache.CreateWatch(req, subscription, responder)
			if err != nil {
				s.opts.Logger.Warnf("[sotw] Watch rejected for type %s and stream %d", typeURL, sw.ID)
				return err
			}
			sw.watches.addWatch(typeURL, &watch{
				cancel:   cancel,
				response: responder,
				sub:      subscription,
			})

			// Recompute the dynamic select cases for this stream.
			sw.watches.recompute(s.ctx, reqCh)
		default:
			// Channel n -> these are the dynamic list of responders that correspond to the stream request typeURL
			// nil is used to close the streams in the caches
			if value.IsNil() || !ok {
				// Receiver channel was closed. TODO(jpeach): probably cancel the watch or something?
				return status.Errorf(codes.Unavailable, "resource watch %d -> failed", index)
			}

			// If a non cache.Response arrived here, there are serious issues
			res := value.Interface().(cache.Response)
			err := sw.send(res)
			if err != nil {
				return err
			}
		}
	}
}
