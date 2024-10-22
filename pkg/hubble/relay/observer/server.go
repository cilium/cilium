// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package observer

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	grpcStatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/hubble/build"
	"github.com/cilium/cilium/pkg/hubble/observer"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
)

// numUnavailableNodesReportMax represents the maximum number of unavailable
// nodes that should be reported on ServerStatus call. The intent is not to be
// exhaustive when listing them as reporting all unavailable nodes might
// clutter in certain cases.
// Reporting up to 10 unavailable nodes is probably reasonable.
const numUnavailableNodesReportMax = 10

// PeerLister is the interface that wraps the List method.
type PeerLister interface {
	// List returns a list of peers with active connections. If a peer cannot
	// be connected to; its Conn attribute must be nil.
	List() []poolTypes.Peer
}

// Server implements the observerpb.ObserverServer interface.
type Server struct {
	opts  options
	peers PeerLister
}

// NewServer creates a new Server.
func NewServer(peers PeerLister, options ...Option) (*Server, error) {
	opts := defaultOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}
	return &Server{
		opts:  opts,
		peers: peers,
	}, nil
}

// GetFlows implements observerpb.ObserverServer.GetFlows by proxying requests to
// the hubble instance the proxy is connected to.
func (s *Server) GetFlows(req *observerpb.GetFlowsRequest, stream observerpb.Observer_GetFlowsServer) error {
	ctx := stream.Context()
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	peers := s.peers.List()
	qlen := s.opts.sortBufferMaxLen // we don't want to buffer too many flows
	if nqlen := req.GetNumber() * uint64(len(peers)); nqlen > 0 && nqlen < uint64(qlen) {
		// don't make the queue bigger than necessary as it would be a problem
		// with the priority queue (we pop out when the queue is full)
		qlen = int(nqlen)
	}

	g, gctx := errgroup.WithContext(ctx)
	flows := make(chan *observerpb.GetFlowsResponse, qlen)

	fc := newFlowCollector(req, s.opts)
	connectedNodes, unavailableNodes := fc.collect(gctx, g, peers, flows)

	if req.GetFollow() {
		go func() {
			updateTimer, updateTimerDone := inctimer.New()
			defer updateTimerDone()
			for {
				select {
				case <-updateTimer.After(s.opts.peerUpdateInterval):
					peers := s.peers.List()
					_, _ = fc.collect(gctx, g, peers, flows)
				case <-gctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		g.Wait()
		close(flows)
	}()

	aggregated := aggregateErrors(ctx, flows, s.opts.errorAggregationWindow)
	sortedFlows := sortFlows(ctx, aggregated, qlen, s.opts.sortBufferDrainTimeout)

	// inform the client about the nodes from which we expect to receive flows first
	if len(connectedNodes) > 0 {
		status := nodeStatusEvent(relaypb.NodeState_NODE_CONNECTED, connectedNodes...)
		if err := stream.Send(status); err != nil {
			return err
		}
	}
	if len(unavailableNodes) > 0 {
		status := nodeStatusEvent(relaypb.NodeState_NODE_UNAVAILABLE, unavailableNodes...)
		if err := stream.Send(status); err != nil {
			return err
		}
	}

	err := sendFlowsResponse(ctx, stream, sortedFlows)
	if err != nil {
		return err
	}
	return g.Wait()
}

// GetAgentEvents implements observerpb.ObserverServer.GetAgentEvents by proxying requests to
// the hubble instance the proxy is connected to.
func (s *Server) GetAgentEvents(req *observerpb.GetAgentEventsRequest, stream observerpb.Observer_GetAgentEventsServer) error {
	return grpcStatus.Errorf(codes.Unimplemented, "GetAgentEvents not yet implemented")
}

// GetDebugEvents implements observerpb.ObserverServer.GetDebugEvents by proxying requests to
// the hubble instance the proxy is connected to.
func (s *Server) GetDebugEvents(req *observerpb.GetDebugEventsRequest, stream observerpb.Observer_GetDebugEventsServer) error {
	return grpcStatus.Errorf(codes.Unimplemented, "GetDebugEvents not yet implemented")
}

// GetNodes implements observerpb.ObserverClient.GetNodes.
func (s *Server) GetNodes(ctx context.Context, req *observerpb.GetNodesRequest) (*observerpb.GetNodesResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	peers := s.peers.List()
	nodes := make([]*observerpb.Node, 0, len(peers))
	for _, p := range peers {
		n := &observerpb.Node{
			Name: p.Name,
			Tls: &observerpb.TLS{
				Enabled:    p.TLSEnabled,
				ServerName: p.TLSServerName,
			},
		}
		if p.Address != nil {
			n.Address = p.Address.String()
		}
		nodes = append(nodes, n)
		if !isAvailable(p.Conn) {
			n.State = relaypb.NodeState_NODE_UNAVAILABLE
			s.opts.log.WithField("address", p.Address).Infof(
				"No connection to peer %s, skipping", p.Name,
			)
			continue
		}
		n.State = relaypb.NodeState_NODE_CONNECTED
		g.Go(func() error {
			n := n
			client := s.opts.ocb.observerClient(&p)
			status, err := client.ServerStatus(ctx, &observerpb.ServerStatusRequest{})
			if err != nil {
				n.State = relaypb.NodeState_NODE_ERROR
				s.opts.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Warning("Failed to retrieve server status")
				return nil
			}
			n.Version = status.GetVersion()
			n.UptimeNs = status.GetUptimeNs()
			n.MaxFlows = status.GetMaxFlows()
			n.NumFlows = status.GetNumFlows()
			n.SeenFlows = status.GetSeenFlows()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return &observerpb.GetNodesResponse{Nodes: nodes}, nil
}

// GetNamespaces implements observerpb.ObserverClient.GetNamespaces.
func (s *Server) GetNamespaces(ctx context.Context, req *observerpb.GetNamespacesRequest) (*observerpb.GetNamespacesResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	// We are not using errgroup.WithContext because we will return partial
	// results over failing on the first error
	g := new(errgroup.Group)

	namespaceManager := observer.NewNamespaceManager()

	for _, p := range s.peers.List() {
		if !isAvailable(p.Conn) {
			s.opts.log.WithField("address", p.Address).Infof(
				"No connection to peer %s, skipping", p.Name,
			)
			continue
		}

		g.Go(func() error {
			client := s.opts.ocb.observerClient(&p)
			nsResp, err := client.GetNamespaces(ctx, req)
			if err != nil {
				s.opts.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Warning("Failed to retrieve namespaces")
				return nil
			}
			for _, ns := range nsResp.GetNamespaces() {
				namespaceManager.AddNamespace(ns)
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return &observerpb.GetNamespacesResponse{Namespaces: namespaceManager.GetNamespaces()}, nil
}

// ServerStatus implements observerpb.ObserverServer.ServerStatus by aggregating
// the ServerStatus answer of all hubble peers.
func (s *Server) ServerStatus(ctx context.Context, req *observerpb.ServerStatusRequest) (*observerpb.ServerStatusResponse, error) {
	var (
		cancel context.CancelFunc
		g      *errgroup.Group
	)
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()
	g, ctx = errgroup.WithContext(ctx)

	peers := s.peers.List()
	mu := lock.Mutex{}
	numUnavailableNodes := 0
	var unavailableNodes []string
	statuses := make(chan *observerpb.ServerStatusResponse, len(peers))
	for _, p := range peers {
		if !isAvailable(p.Conn) {
			s.opts.log.WithField("address", p.Address).Infof(
				"No connection to peer %s, skipping", p.Name,
			)
			mu.Lock()
			numUnavailableNodes++
			if len(unavailableNodes) < numUnavailableNodesReportMax {
				unavailableNodes = append(unavailableNodes, p.Name)
			}
			mu.Unlock()
			continue
		}

		g.Go(func() error {
			client := s.opts.ocb.observerClient(&p)
			status, err := client.ServerStatus(ctx, req)
			if err != nil {
				s.opts.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Warning("Failed to retrieve server status")
				mu.Lock()
				numUnavailableNodes++
				if len(unavailableNodes) < numUnavailableNodesReportMax {
					unavailableNodes = append(unavailableNodes, p.Name)
				}
				mu.Unlock()
				return nil
			}
			select {
			case statuses <- status:
			case <-ctx.Done():
			}
			return nil
		})
	}
	go func() {
		g.Wait()
		close(statuses)
	}()
	resp := &observerpb.ServerStatusResponse{
		Version: build.RelayVersion.String(),
	}
	for status := range statuses {
		if status == nil {
			continue
		}
		resp.MaxFlows += status.MaxFlows
		resp.NumFlows += status.NumFlows
		resp.SeenFlows += status.SeenFlows
		// use the oldest uptime as a reference for the uptime as cumulating
		// values would make little sense
		if resp.UptimeNs < status.UptimeNs {
			resp.UptimeNs = status.UptimeNs
		}
		resp.FlowsRate += status.FlowsRate
	}

	resp.NumConnectedNodes = &wrapperspb.UInt32Value{
		Value: uint32(len(peers) - numUnavailableNodes),
	}
	resp.NumUnavailableNodes = &wrapperspb.UInt32Value{
		Value: uint32(numUnavailableNodes),
	}
	resp.UnavailableNodes = unavailableNodes

	return resp, g.Wait()
}
