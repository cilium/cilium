// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package xds

import (
	"context"
	"errors"
	"io"
	"time"

	envoy_service_discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// MockStream is a mock implementation of Stream used for testing.
type MockStream struct {
	ctx         context.Context
	recv        chan *envoy_service_discovery.DiscoveryRequest
	sent        chan *envoy_service_discovery.DiscoveryResponse
	recvTimeout time.Duration
	sentTimeout time.Duration
}

// NewMockStream creates a new mock Stream for testing.
func NewMockStream(ctx context.Context, recvSize, sentSize int, recvTimeout, sentTimeout time.Duration) *MockStream {
	return &MockStream{
		ctx:         ctx,
		recv:        make(chan *envoy_service_discovery.DiscoveryRequest, recvSize),
		sent:        make(chan *envoy_service_discovery.DiscoveryResponse, sentSize),
		recvTimeout: recvTimeout,
		sentTimeout: sentTimeout,
	}
}

func (s *MockStream) Send(resp *envoy_service_discovery.DiscoveryResponse) error {
	subCtx, cancel := context.WithTimeout(s.ctx, s.sentTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if errors.Is(subCtx.Err(), context.Canceled) {
			return io.EOF
		}
		return subCtx.Err()
	case s.sent <- resp:
		cancel()
		return nil
	}
}

func (s *MockStream) Recv() (*envoy_service_discovery.DiscoveryRequest, error) {
	subCtx, cancel := context.WithTimeout(s.ctx, s.recvTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if errors.Is(subCtx.Err(), context.Canceled) {
			return nil, io.EOF
		}
		return nil, subCtx.Err()
	case req := <-s.recv:
		cancel()
		if req == nil {
			return nil, io.EOF
		}
		return req, nil
	}
}

// SendRequest queues a request to be received by calling Recv.
func (s *MockStream) SendRequest(req *envoy_service_discovery.DiscoveryRequest) error {
	subCtx, cancel := context.WithTimeout(s.ctx, s.recvTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if errors.Is(subCtx.Err(), context.Canceled) {
			return io.EOF
		}
		return subCtx.Err()
	case s.recv <- req:
		cancel()
		return nil
	}
}

// RecvResponse receives a response that was queued by calling Send.
func (s *MockStream) RecvResponse() (*envoy_service_discovery.DiscoveryResponse, error) {
	subCtx, cancel := context.WithTimeout(s.ctx, s.sentTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if errors.Is(subCtx.Err(), context.Canceled) {
			return nil, io.EOF
		}
		return nil, subCtx.Err()
	case resp := <-s.sent:
		cancel()
		return resp, nil
	}
}

// Close closes the resources used by this MockStream.
func (s *MockStream) Close() {
	close(s.recv)
	close(s.sent)
}
