// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"context"
	"errors"
	"io"

	"github.com/cilium/statedb"
	"golang.org/x/sync/errgroup"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// ErrStreamSendBlocked is returned by Notify when the send operation is
// blocked for too long, likely indicating a problem with the transport.
var ErrStreamSendBlocked = errors.New("server stream send was blocked for too long")

// Service implements the peerpb.PeerServer gRPC service.
type Service struct {
	stop  chan struct{}
	db    *statedb.DB
	nodes statedb.Table[*node.Node]
	opts  serviceoption.Options
}

// Ensure that Service implements the peerpb.PeerServer interface.
var _ peerpb.PeerServer = (*Service)(nil)

// NewService creates a new Service.
func NewService(db *statedb.DB, nodes statedb.Table[*node.Node], options ...serviceoption.Option) *Service {
	opts := serviceoption.Default
	for _, opt := range options {
		opt(&opts)
	}
	return &Service{
		stop:  make(chan struct{}),
		db:    db,
		nodes: nodes,
		opts:  opts,
	}
}

// Notify implements peerpb.Peer_PeerServer.Notify. If the client is not able
// to process change notifications fast enough, the server will terminate the
// connection.
func (s *Service) Notify(_ *peerpb.NotifyRequest, stream peerpb.Peer_NotifyServer) error {
	wtxn := s.db.WriteTxn(s.nodes)
	changes, err := s.nodes.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}
	defer changes.Close()

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	// monitor for global stop signal to tear down all routines
	h := newHandler(s.opts.WithoutTLSInfo, s.opts.AddressFamilyPreference, s.opts.HubblePort)
	g.Go(func() error {
		defer h.Close()
		select {
		case <-s.stop:
			cancel()
			return nil
		case <-ctx.Done():
			return nil
		}
	})

	// Translate the initial node snapshot and subsequent table changes into
	// notifications. Keep the previous version to suppress updates that do not
	// change the peer's address.
	g.Go(func() error {
		// Process change bursts at most once every 50 milliseconds. The initial
		// snapshot is processed immediately before the limiter is consulted.
		limiter := rate.NewLimiter(50*time.Millisecond, 1)
		defer limiter.Stop()

		previous := map[string]*node.Node{}
		for {
			seq, watch := changes.Next(s.db.ReadTxn())
			for change := range seq {
				n := change.Object
				name := n.Fullname()
				if change.Deleted {
					h.nodeDeleted(n.Node)
					delete(previous, name)
				} else if old, found := previous[name]; found {
					h.nodeUpdated(old.Node, n.Node)
					previous[name] = n
				} else {
					h.nodeAdded(n.Node)
					previous[name] = n
				}
			}

			select {
			case <-ctx.Done():
				return nil
			case <-watch:
			}
			if limiter.Wait(ctx) != nil {
				return nil
			}
		}
	})

	// read from the handler's channel and fill the buffer until it's full
	buf := newBuffer(s.opts.MaxSendBufferSize)
	g.Go(func() error {
		defer buf.Close()
		for {
			select {
			case cn, ok := <-h.C:
				if !ok {
					// channel is closed, stop buffering
					return nil
				}
				if err := buf.Push(cn); err != nil {
					return ErrStreamSendBlocked
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	// read from the buffer end send to the client
	g.Go(func() error {
		for {
			cn, err := buf.Pop()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			if err := stream.Send(cn); err != nil {
				return err
			}
		}
	})

	return g.Wait()
}

// Close frees resources associated to the Service.
func (s *Service) Close() error {
	close(s.stop)
	return nil
}
