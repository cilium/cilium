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
	"github.com/sirupsen/logrus"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ensure that Server implements the observer.ObserverServer interface.
var _ observerpb.ObserverServer = (*Server)(nil)

func newObserverClient(target string, dialTimeout time.Duration) (observerpb.ObserverClient, *grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	//FIXME: remove WithInsecure once mutual TLS is implemented
	conn, err := grpc.DialContext(ctx, target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, nil, err
	}
	return observerpb.NewObserverClient(conn), conn, nil
}

// GetFlows implements observer.ObserverServer.GetFlows by proxying requests to
// the hubble instance the proxy is connected to.
func (s *Server) GetFlows(req *observerpb.GetFlowsRequest, stream observerpb.Observer_GetFlowsServer) error {
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

	//TODO: figure out what makes a reasonnable channel size
	peers := s.peerList()
	flows := make(chan *observerpb.GetFlowsResponse, 10*len(peers))
	for _, p := range peers {
		p := p
		g.Go(func() error {
			//FIXME: establishing a new connection to every peer for every
			// request is costly. Possible solutions:
			// - selective connection: only connect to peers that have the
			//   requested information (it still has the cost of connect/disconnect per
			//   GetFlows request but it's at least limited in terms of scope).
			// - Maintain a connection with all peers and reconnect when necessary.
			cl, conn, err := newObserverClient(p.Address.String(), s.opts.DialTimeout)
			if err != nil {
				s.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Error("Failed to connect to peer")
				return nil
			}
			defer conn.Close()
			c, err := cl.GetFlows(ctx, req)
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
						s.log.WithFields(logrus.Fields{
							"error": err,
							"peer":  p,
						}).Error("Failed to receive flows from peer")
					}
					return nil
				}
			}
		})
	}
	go func() {
		g.Wait()
		close(flows)
	}()
	//TODO: flows are sent in the order they are received. One should make use
	// of pkg/hubble/container/PriorityQueue to re-order flows (to the extent of
	// what seems reasonnable)
	for flow := range flows {
		if err := stream.Send(flow); err != nil {
			return err
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
		g.Go(func() error {
			//FIXME: establishing a new connection to every peer for every
			// request is costly. Possible solutions:
			// - selective connection: only connect to peers that have the
			//   requested information (it still has the cost of connect/disconnect per
			//   ServerStatus request but it's at least limited in terms of scope).
			// - Maintain a connection with all peers and reconnect when necessary.
			cl, conn, err := newObserverClient(p.Address.String(), s.opts.DialTimeout)
			if err != nil {
				s.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Error("Failed to connect to peer")
				return nil
			}
			defer conn.Close()
			status, err := cl.ServerStatus(ctx, req)
			if err != nil {
				s.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p,
				}).Error("Failed to retrieve server status")
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
