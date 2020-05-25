// Copyright 2020 Authors of Cilium
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

package relay

import (
	"context"
	"io"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/relay/queue"
	"github.com/sirupsen/logrus"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ensure that Server implements the observer.ObserverServer interface.
var _ observerpb.ObserverServer = (*Server)(nil)

func retrieveFlowsFromPeer(
	ctx context.Context,
	conn *grpc.ClientConn,
	req *observerpb.GetFlowsRequest,
	flows chan<- *observerpb.GetFlowsResponse,
) error {
	client := observerpb.NewObserverClient(conn)
	c, err := client.GetFlows(ctx, req)
	if err != nil {
		return err
	}
	for {
		flow, err := c.Recv()
		switch err {
		case io.EOF, context.Canceled:
			return nil
		case nil:
			select {
			case flows <- flow:
			case <-ctx.Done():
				return nil
			}
		default:
			if status.Code(err) != codes.Canceled {
				return err
			}
			return nil
		}
	}
}

func sortFlows(
	ctx context.Context,
	flows <-chan *observerpb.GetFlowsResponse,
	qlen int,
	bufferDrainTimeout time.Duration,
) <-chan *observerpb.GetFlowsResponse {
	pq := queue.NewPriorityQueue(qlen)
	sortedFlows := make(chan *observerpb.GetFlowsResponse, qlen)

	go func() {
		defer close(sortedFlows)

	flowsLoop:
		for {
			select {
			case flow, ok := <-flows:
				if !ok {
					break flowsLoop
				}
				if pq.Len() == qlen {
					f := pq.Pop()
					select {
					case sortedFlows <- f:
					case <-ctx.Done():
						return
					}
				}
				pq.Push(flow)
			case <-time.After(bufferDrainTimeout): // make sure to drain the queue when no new flow responses are received
				if f := pq.Pop(); f != nil {
					select {
					case sortedFlows <- f:
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
		// drain the queue
		for f := pq.Pop(); f != nil; f = pq.Pop() {
			select {
			case sortedFlows <- f:
			case <-ctx.Done():
				return
			}
		}

	}()

	return sortedFlows
}

// GetFlows implements observer.ObserverServer.GetFlows by proxying requests to
// the hubble instance the proxy is connected to.
func (s *Server) GetFlows(req *observerpb.GetFlowsRequest, stream observerpb.Observer_GetFlowsServer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	peers := s.peerList()
	qlen := s.opts.BufferMaxLen // we don't want to buffer too many flows
	if nqlen := req.GetNumber() * uint64(len(peers)); nqlen > 0 && nqlen < uint64(qlen) {
		// don't make the queue bigger than necessary as it would be a problem
		// with the priority queue (we pop out when the queue is full)
		qlen = int(nqlen)
	}

	g, gctx := errgroup.WithContext(ctx)
	flows := make(chan *observerpb.GetFlowsResponse, qlen)
	for _, p := range peers {
		p := p
		if p.conn == nil || p.connErr != nil {
			s.log.WithField("address", p.Address.String()).Infof(
				"No connection to peer %s, skipping", p.Name,
			)
			go s.connectPeer(p.Name, p.Address.String())
			continue
		}
		g.Go(func() error {
			// retrieveFlowsFromPeer returns blocks until the peer finishes
			// the request by closing the connection, an error occurs,
			// or gctx expires.
			err := retrieveFlowsFromPeer(gctx, p.conn, req, flows)
			if err != nil {
				s.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Warning("Failed to retrieve flows from peer")
			}
			return nil
		})
	}
	go func() {
		g.Wait()
		close(flows)
	}()

	sortedFlows := sortFlows(ctx, flows, qlen, s.opts.BufferDrainTimeout)

sortedFlowsLoop:
	for {
		select {
		case flow, ok := <-sortedFlows:
			if !ok {
				break sortedFlowsLoop
			}
			if err := stream.Send(flow); err != nil {
				return err
			}
		case <-ctx.Done():
			break sortedFlowsLoop
		}
	}
	return g.Wait()
}

// ServerStatus implements observer.ObserverServer.ServerStatus by aggregating
// the ServerStatus answer of all hubble peers.
func (s *Server) ServerStatus(ctx context.Context, req *observerpb.ServerStatusRequest) (*observerpb.ServerStatusResponse, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)
	go func() {
		select {
		case <-s.stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	peers := s.peerList()
	statuses := make(chan *observerpb.ServerStatusResponse, len(peers))
	for _, p := range peers {
		p := p
		if p.conn == nil || p.connErr != nil {
			s.log.WithField("address", p.Address.String()).Infof(
				"No connection to peer %s, skipping", p.Name,
			)
			go s.connectPeer(p.Name, p.Address.String())
			continue
		}
		g.Go(func() error {
			client := observerpb.NewObserverClient(p.conn)
			status, err := client.ServerStatus(ctx, req)
			if err != nil {
				s.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Warning("Failed to retrieve server status")
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
	resp := &observerpb.ServerStatusResponse{}
	for status := range statuses {
		if status == nil {
			continue
		}
		resp.MaxFlows += status.MaxFlows
		resp.NumFlows += status.NumFlows
		resp.SeenFlows += status.SeenFlows
		// use the oldest uptime as a reference for the uptime as cumulating
		// values would make little sense
		if resp.UptimeNs == 0 || resp.UptimeNs > status.UptimeNs {
			resp.UptimeNs = status.UptimeNs
		}
	}
	return resp, g.Wait()
}
