package sotw

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/stream/v3"
)

// process handles a bi-di stream request
func (s *server) processADS(sw *streamWrapper, reqCh chan *discovery.DiscoveryRequest) error {
	// Create a buffered multiplexed channel the size of the known resource types.
	respChan := make(chan cache.Response, types.UnknownType)

	// Instead of creating a separate channel for each incoming request and abandoning the old one
	// This algorithm uses (and reuses) a single channel for all request types and guarantees
	// the server will send updates over the wire in an ordered fashion.
	// Downside is there is no longer back pressure per resource.
	// There is potential for a dropped response from the cache but this is not impactful
	// to the client since SOTW version handling is global and a new sequence will be
	// initiated on a new request.
	processAllExcept := func(typeURL string) error {
		for {
			select {
			// We watch the multiplexed ADS channel for incoming responses.
			case res := <-respChan:
				if res.GetRequest().GetTypeUrl() != typeURL {
					if err := sw.send(res); err != nil {
						return err
					}
				}
			default:
				return nil
			}
		}
	}

	// This control loop strictly orders resources when running in ADS mode.
	// It should be treated as a child process of the original process() loop
	// and should return on close of stream or error. This will cause the
	// cleanup routines in the parent process() loop to execute.
	for {
		select {
		case <-s.ctx.Done():
			return nil
		// We only watch the multiplexed channel since we don't use per watch channels.
		case res := <-respChan:
			if err := sw.send(res); err != nil {
				return status.Errorf(codes.Unavailable, err.Error())
			}
		case req, ok := <-reqCh:
			// Input stream ended or failed.
			if !ok {
				return nil
			}

			// Received an empty request over the request channel. Can't respond.
			if req == nil {
				return status.Errorf(codes.Unavailable, "empty request")
			}

			// Only first request is guaranteed to hold node info so if it's missing, reassign.
			if req.GetNode() != nil {
				sw.node = req.GetNode()
			} else {
				req.Node = sw.node
			}

			// type URL is required for ADS but is implicit for xDS
			typeURL := req.GetTypeUrl()
			if typeURL == "" {
				return status.Errorf(codes.InvalidArgument, "type URL is required for ADS")
			}

			if s.callbacks != nil {
				if err := s.callbacks.OnStreamRequest(sw.ID, req); err != nil {
					return err
				}
			}

			var subscription stream.Subscription
			w, ok := sw.watches.responders[typeURL]
			if ok {
				if w.nonce != "" && req.GetResponseNonce() != w.nonce {
					// The request does not match the stream nonce, ignore it as per
					// https://www.envoyproxy.io/docs/envoy/v1.28.0/api-docs/xds_protocol#resource-updates
					// Ignore this request and wait for the next one
					// This behavior is being discussed in https://github.com/envoyproxy/envoy/issues/10363
					// as it might create a race in edge cases, but it matches the current protocol definition
					s.opts.Logger.Infof("[sotw ads] Skipping request as nonce is stale for %s", typeURL)
					break
				}

				// We found an existing watch
				// Close it to ensure the Cache will not reply to it while we modify the subscription state
				w.close()

				// Only process if we have an existing watch otherwise go ahead and create.
				if err := processAllExcept(typeURL); err != nil {
					return err
				}

				subscription = w.sub
				subscription.SetResourceSubscription(req.GetResourceNames())
			} else {
				s.opts.Logger.Debugf("[sotw ads] New subscription for type %s and stream %d", typeURL, sw.ID)
				subscription = stream.NewSotwSubscription(req.GetResourceNames(), s.opts.IsLegacyWildcardActive(typeURL))
			}

			cancel, err := s.cache.CreateWatch(req, subscription, respChan)
			if err != nil {
				return err
			}
			sw.watches.addWatch(typeURL, &watch{
				cancel:   cancel,
				response: respChan,
				sub:      subscription,
			})
		}
	}
}
