// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package peer

import (
	"context"
	"errors"
	"io"

	"golang.org/x/sync/errgroup"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/peer/serviceoption"
	"github.com/cilium/cilium/pkg/node/manager"
)

// ErrStreamSendBlocked is returned by Notify when the send operation is
// blocked for too long, likely indicating a problem with the transport.
var ErrStreamSendBlocked = errors.New("server stream send was blocked for too long")

// Service implements the peerpb.PeerServer gRPC service.
type Service struct {
	stop     chan struct{}
	notifier manager.Notifier
	opts     serviceoption.Options
}

// Ensure that Service implements the peerpb.PeerServer interface.
var _ peerpb.PeerServer = (*Service)(nil)

// NewService creates a new Service.
func NewService(notifier manager.Notifier, options ...serviceoption.Option) *Service {
	opts := serviceoption.Default
	for _, opt := range options {
		opt(&opts)
	}
	return &Service{
		stop:     make(chan struct{}),
		notifier: notifier,
		opts:     opts,
	}
}

// Notify implements peerpb.Peer_PeerServer.Notify. If the client is not able
// to process change notifications fast enough, the server will terminate the
// connection.
func (s *Service) Notify(_ *peerpb.NotifyRequest, stream peerpb.Peer_NotifyServer) error {
	// The node manager sends notifications upon call to Subscribe. As the
	// handler's channel is unbuffered, make sure that the client is ready to
	// read notifications to avoid a deadlock situation.
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	// monitor for global stop signal to tear down all routines
	h := newHandler(s.opts.WithoutTLSInfo, s.opts.AddressFamilyPreference)
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
			switch err {
			case nil:
				if err := stream.Send(cn); err != nil {
					return err
				}
			case io.EOF:
				return nil
			default:
				return err
			}
		}
	})

	s.notifier.Subscribe(h)
	defer s.notifier.Unsubscribe(h)
	return g.Wait()
}

// Close frees resources associated to the Service.
func (s *Service) Close() error {
	close(s.stop)
	return nil
}
