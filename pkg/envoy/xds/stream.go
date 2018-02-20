// Copyright 2018 Authors of Cilium
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

package xds

import (
	"context"
	"io"
	"time"

	envoy_api_v2 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2"
)

// Stream is the subset of the gRPC bi-directional stream types which is used
// by Server.
type Stream interface {
	// Send sends a xDS response back to the client.
	Send(*envoy_api_v2.DiscoveryResponse) error

	// Recv receives a xDS request from the client.
	Recv() (*envoy_api_v2.DiscoveryRequest, error)
}

// MockStream is a mock implementation of Stream used for testing.
type MockStream struct {
	ctx         context.Context
	recv        chan *envoy_api_v2.DiscoveryRequest
	sent        chan *envoy_api_v2.DiscoveryResponse
	recvTimeout time.Duration
	sentTimeout time.Duration
}

// NewMockStream creates a new mock Stream for testing.
func NewMockStream(ctx context.Context, recvSize, sentSize int, recvTimeout, sentTimeout time.Duration) *MockStream {
	return &MockStream{
		ctx:         ctx,
		recv:        make(chan *envoy_api_v2.DiscoveryRequest, recvSize),
		sent:        make(chan *envoy_api_v2.DiscoveryResponse, sentSize),
		recvTimeout: recvTimeout,
		sentTimeout: sentTimeout,
	}
}

func (s *MockStream) Send(resp *envoy_api_v2.DiscoveryResponse) error {
	subCtx, cancel := context.WithTimeout(s.ctx, s.sentTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if subCtx.Err() == context.Canceled {
			return io.EOF
		}
		return subCtx.Err()
	case s.sent <- resp:
		cancel()
		return nil
	}
}

func (s *MockStream) Recv() (*envoy_api_v2.DiscoveryRequest, error) {
	subCtx, cancel := context.WithTimeout(s.ctx, s.recvTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if subCtx.Err() == context.Canceled {
			return nil, io.EOF
		}
		return nil, subCtx.Err()
	case req := <-s.recv:
		cancel()
		return req, nil
	}
}

// SendRequest queues a request to be received by calling Recv.
func (s *MockStream) SendRequest(req *envoy_api_v2.DiscoveryRequest) error {
	subCtx, cancel := context.WithTimeout(s.ctx, s.recvTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if subCtx.Err() == context.Canceled {
			return io.EOF
		}
		return subCtx.Err()
	case s.recv <- req:
		cancel()
		return nil
	}
}

// RecvResponse receives a response that was queued by calling Send.
func (s *MockStream) RecvResponse() (*envoy_api_v2.DiscoveryResponse, error) {
	subCtx, cancel := context.WithTimeout(s.ctx, s.sentTimeout)

	select {
	case <-subCtx.Done():
		cancel()
		if subCtx.Err() == context.Canceled {
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
