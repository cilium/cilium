// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/logging/logfields"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// requestConstraint is a constraint for request messages in xDS protocol.
type requestConstraint interface {
	*discoverypb.DiscoveryRequest | *discoverypb.DeltaDiscoveryRequest
}

// responseConstraint is a constraint for response messages in xDS protocol.
type responseConstraint interface {
	*discoverypb.DiscoveryResponse | *discoverypb.DeltaDiscoveryResponse
	GetTypeUrl() string
}

// transport is a common generic interface of xDS gRPC client.
type transport[req requestConstraint, resp responseConstraint] interface {
	Send(req) error
	Recv() (resp, error)
}

// nameToResource maps a resource name to a proto representation of the resource.
type nameToResource map[string]proto.Message

// tx represents a transaction prepared based on {Delta,}DiscoveryResponse.
type tx struct {
	typeUrl string
	updated nameToResource
	deleted []string
}

type txs []tx

// getter specifies function to retrieve all resources of given type url.
type getter func(typeUrl string) (*xds.VersionedResources, error)

// flavour specifies a common interface for implementations specific to sotw or
// delta protocol version. It is primarily used by XDSClient.
type flavour[ReqT requestConstraint, RespT responseConstraint] interface {
	// transport constructs an instance of a transport based on the provided xDS ADS gRPC client.
	transport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[ReqT, RespT], error)

	// prepareObsReq creates a request based on parameters used in Observe calls.
	// get may be used to obtain the current contents of clients cache.
	prepareObsReq(obsReq *observeRequest, node *corepb.Node, get getter) (request ReqT, err error)

	// tx prepares a list of transactions based on a given response.
	// get may be used to obtain the current contents of clients cache.
	tx(resp RespT, get getter) (transactions txs, err error)

	// ack constructs request serving as ACKnowledgment of the given response.
	ack(node *corepb.Node, resp RespT, resourceNames []string) (request ReqT)

	// nack constructs request serving to inform the xDS server that their last
	// response was Not ACKnowledged.
	nack(node *corepb.Node, resp RespT, detail error) (request ReqT)
}

// Client is the public interface of xDS client.
type Client interface {
	// Observe adds resources of given type url and names to the attention set
	// of the client.
	Observe(ctx context.Context, typeUrl string, resourceNames []string) error

	// AddResourceWatcher registers a callback cb that will be invoked every
	// time a resource with given type url changes. Function returns a callback
	// to deregister the watcher.
	AddResourceWatcher(typeUrl string, cb WatcherCallback) func()

	// Run initialize the node and start an AggregatedDiscoverService stream.
	// Requests and responses are processed until provided Context ctx is
	// done or non-retriable error occurs.
	Run(ctx context.Context, node *corepb.Node, conn grpc.ClientConnInterface) error
}

// XDSClient implements Client.
var _ Client = (*XDSClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse])(nil)
var _ Client = (*XDSClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse])(nil)

// observeRequest is an internal representation of call to Observe method.
type observeRequest struct {
	// For example: "type.googleapis.com/envoy.config.listener.v3.Listener"
	typeUrl       string
	resourceNames []string
}

// XDSClient is a common part of xDS gRPC client implementation using flavour to
// implement xDS protocol version specific behaviors.
type XDSClient[ReqT requestConstraint, RespT responseConstraint] struct {
	log  *slog.Logger
	opts ConnectionOptions

	observeQueue  chan *observeRequest
	responseQueue chan RespT

	node *corepb.Node
	xds  flavour[ReqT, RespT]

	// cache stores versioned resources.
	cache *xds.Cache
	// watchers manages callbacks with notification when cache state changes.
	watchers *callbackManager
}

// NewClient creates a new instance of XDSClient using sotw or delta protocol
// flavour based on options opts.
func NewClient(log *slog.Logger, useSOTW bool, opts *ConnectionOptions) Client {
	if useSOTW {
		return newClient[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse](log, opts, &sotw{})
	}
	return newClient[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse](log, opts, &delta{})
}

func newClient[ReqT requestConstraint, RespT responseConstraint](log *slog.Logger, opts *ConnectionOptions, flavour flavour[ReqT, RespT]) *XDSClient[ReqT, RespT] {
	cache := xds.NewCache(log)

	return &XDSClient[ReqT, RespT]{
		log:           log,
		opts:          *opts,
		observeQueue:  make(chan *observeRequest, 1),
		responseQueue: make(chan RespT, 1),
		xds:           flavour,
		cache:         cache,
		watchers:      newCallbackManager(log.With(logfields.Hint, "watchers"), cache),
	}
}

// Run initialize the node and start an AggregatedDiscoverService stream. Then
// requests and responses are processed until provided Context ctx is done or
// non-retriable error occurs.
func (c *XDSClient[ReqT, RespT]) Run(ctx context.Context, node *corepb.Node, conn grpc.ClientConnInterface) error {
	// node is used to identify a client to xDS server. Nodes's value is retried
	// from LocalNodeStore and it needs to be late initialized.
	c.node = proto.Clone(node).(*corepb.Node)
	c.log.Info("starting xDS client with node",
		logfields.EnvoyID, c.node.Id,
		logfields.EnvoyCluster, c.node.Cluster,
		logfields.UserAgent, c.node.UserAgentName,
	)
	backoff := backoff.Exponential{
		Logger:     c.log,
		Min:        c.opts.RetryBackoff.Min,
		Max:        c.opts.RetryBackoff.Max,
		ResetAfter: c.opts.RetryBackoff.Reset,
		Jitter:     true,
		Name:       "xds-client-conn",
	}
	client := discoverypb.NewAggregatedDiscoveryServiceClient(conn)

	for {
		err := c.process(ctx, client)

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !c.opts.RetryConnection {
			return err
		}
		c.log.Error("Retrying connection", logfields.Error, err)
		err = backoff.Wait(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return fmt.Errorf("connection retry backoff: %w", err)
			}
		}
	}
}

// process creates a transport, sends initial requests and spins up two additional goroutines:
//   - fetchResponses which passes objects from Recv calls onto a queue
//   - loop which processes responses queued up by fetchResponses goroutine, and
//     processes requests queued up by calls to Observe method
//
// If any of the goroutines fails with non-retryable error, or terminates, it
// will stop the transport (by cancelling its context) and wait for all
// goroutines started by it to finish processing.
func (c *XDSClient[ReqT, RespT]) process(parentCtx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) error {
	ctx, cancel := context.WithCancel(parentCtx)

	trans, err := c.xds.transport(ctx, client)
	if err != nil {
		cancel()
		return fmt.Errorf("start transport: %w", err)
	}

	errRespCh := make(chan error, 1)
	go c.fetchResponses(ctx, errRespCh, trans)
	errLoopCh := make(chan error, 1)
	go c.loop(ctx, errLoopCh, trans)

	defer func() {
		cancel()
		<-errLoopCh
		<-errRespCh
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err, ok := <-errRespCh:
			if !ok {
				return fmt.Errorf("process responses: terminated")
			}
			if c.isRetriableErr(err) {
				continue
			}
			return fmt.Errorf("process responses: %w", err)
		case err, ok := <-errLoopCh:
			if !ok {
				return fmt.Errorf("process loop: terminated")
			}
			if c.isRetriableErr(err) {
				continue
			}
			return fmt.Errorf("process loop: %w", err)
		}
	}
}

// isRetriableErr checks if the connection is not terminated and code is
// temporary (configured with opts.IsRetriable).
func (c *XDSClient[ReqT, RespT]) isRetriableErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return false
	}
	return c.opts.IsRetriable(status.Code(err))
}

// fetchResponses will pass messages from Recv() calls to queue until Context ctx is done.
func (c *XDSClient[ReqT, RespT]) fetchResponses(ctx context.Context, errCh chan error, trans transport[ReqT, RespT]) {
	defer close(errCh)
	log := c.log.With(logfields.Hint, "fetch-responses")
	backoff := backoff.Exponential{
		Logger:     c.log,
		Min:        c.opts.RetryBackoff.Min,
		Max:        c.opts.RetryBackoff.Max,
		ResetAfter: c.opts.RetryBackoff.Reset,
		Jitter:     true,
		Name:       "xds-client-fetch-responses",
	}
	for {
		resp, err := trans.Recv()
		if err != nil {
			log.Error("Failed to receive message", logfields.Error, err)
			err = fmt.Errorf("recv: %w", err)
			select {
			case <-ctx.Done():
				return
			case errCh <- err:
				backoff.Wait(ctx)
			}
			continue
		}

		select {
		case <-ctx.Done():
			return
		case c.responseQueue <- resp:
		}
	}
}

func (c *XDSClient[ReqT, RespT]) getAllResources(typeUrl string) (*xds.VersionedResources, error) {
	return c.cache.GetResources(typeUrl, 0, "", nil)
}

// Observe adds resourceNames to watched resources of a given typeUrl.
// It will be sent to a server asynchronously.
func (c *XDSClient[ReqT, RespT]) Observe(ctx context.Context, typeUrl string, resourceNames []string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case c.observeQueue <- &observeRequest{typeUrl: typeUrl, resourceNames: resourceNames}:
	}
	return nil
}

// loop will process responses from transport trans until Context ctx is done.
// Errors are logged and processing continues.
func (c *XDSClient[ReqT, RespT]) loop(ctx context.Context, errCh chan error, trans transport[ReqT, RespT]) {
	defer close(errCh)
	log := c.log.With(logfields.Hint, "loop")
	backoff := backoff.Exponential{
		Logger:     c.log,
		Min:        c.opts.RetryBackoff.Min,
		Max:        c.opts.RetryBackoff.Max,
		ResetAfter: c.opts.RetryBackoff.Reset,
		Jitter:     true,
		Name:       "xds-client-loop",
	}
	log.Info("start processing loop")
	for {
		select {
		case <-ctx.Done():
			return
		case obsReq, ok := <-c.observeQueue:
			log.Debug("got observe msg from the queue", logfields.Request, obsReq)
			if !ok {
				return
			}
			err := c.handleObserve(trans, obsReq)
			if err != nil {
				log.Error("Failed to handle observe",
					logfields.Request, obsReq,
					logfields.Error, err)
				select {
				case <-ctx.Done():
					return
				case errCh <- err:
					backoff.Wait(ctx)
				}
			}
		case resp, ok := <-c.responseQueue:
			if !ok {
				return
			}
			log.Debug("Receive", logfields.Response, resp)
			err := c.handleResponse(trans, resp)
			if err != nil {
				log.Error("Failed to handle response", logfields.Error, err)
				select {
				case <-ctx.Done():
					return
				case errCh <- err:
				}
				req := c.xds.nack(c.node, resp, err)
				err = trans.Send(req)
				if err != nil {
					log.Error("Failed to send NACK", logfields.Error, err)
				}
				backoff.Wait(ctx)
			}
		}
	}
}

// handleObserve creates a flavour-specific request based on observeRequest and sends it on given transport trans.
func (c *XDSClient[ReqT, RespT]) handleObserve(trans transport[ReqT, RespT], obsReq *observeRequest) error {
	req, err := c.xds.prepareObsReq(obsReq, c.node, c.getAllResources)
	if err != nil {
		return fmt.Errorf("prepare observe request: %w", err)
	}
	c.log.Debug("Send", logfields.Request, req)

	err = trans.Send(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

// handleResponse creates transactions based on flavour-specific responses, applies them to cache.
func (c *XDSClient[ReqT, RespT]) handleResponse(trans transport[ReqT, RespT], resp RespT) error {
	transactions, err := c.xds.tx(resp, c.getAllResources)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	for _, transaction := range transactions {
		c.log.Debug("cache TX: start",
			logfields.XDSTypeURL, transaction.typeUrl,
			logfields.Upserted, transaction.updated,
			logfields.Deleted, transaction.deleted,
		)
		ver, updated, _ := c.cache.TX(transaction.typeUrl, transaction.updated, transaction.deleted)
		c.log.Debug("cache TX: end",
			logfields.XDSTypeURL, transaction.typeUrl,
			logfields.XDSCachedVersion, ver,
			logfields.Updated, updated,
		)
	}
	req := c.xds.ack(c.node, resp, nil)

	c.log.Debug("Send", logfields.Request, req)
	err = trans.Send(req)
	if err != nil {
		return fmt.Errorf("ACK send: %w", err)
	}
	return nil
}

func (c *XDSClient[ReqT, RespT]) AddResourceWatcher(typeUrl string, cb WatcherCallback) func() {
	id := c.watchers.Add(typeUrl, cb)
	cancel := func() {
		c.watchers.Remove(id)

	}
	return cancel
}
