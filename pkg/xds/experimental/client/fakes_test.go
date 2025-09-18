// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"context"
	"time"

	discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
)

type fakeStream struct {
	grpc.ClientStream
	OnSend func(*discoverypb.DiscoveryRequest) error
	OnRecv func() (*discoverypb.DiscoveryResponse, error)
}

func (f *fakeStream) Send(r *discoverypb.DiscoveryRequest) error {
	if f.OnSend != nil {
		return f.OnSend(r)
	}
	return nil
}

func (f *fakeStream) Recv() (*discoverypb.DiscoveryResponse, error) {
	if f.OnRecv != nil {
		return f.OnRecv()
	}
	// Avoid hogging CPU during test
	time.Sleep(time.Millisecond)
	return nil, nil
}

var _ discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient = new(fakeStream)

type fakeDelta struct {
	grpc.ClientStream
	OnSend func(*discoverypb.DeltaDiscoveryRequest) error
	OnRecv func() (*discoverypb.DeltaDiscoveryResponse, error)
}

func (f *fakeDelta) Send(r *discoverypb.DeltaDiscoveryRequest) error {
	return f.OnSend(r)
}

func (f *fakeDelta) Recv() (*discoverypb.DeltaDiscoveryResponse, error) {
	return f.OnRecv()
}

var _ discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient = new(fakeDelta)

type fakeClient struct {
	sendErrCh    chan error
	sendStreamCh chan *discoverypb.DiscoveryRequest
	sendDeltaCh  chan *discoverypb.DeltaDiscoveryRequest
	recvCh       chan error
	recvStreamCh chan *discoverypb.DiscoveryResponse
	recvDeltaCh  chan *discoverypb.DeltaDiscoveryResponse
}

var _ discoverypb.AggregatedDiscoveryServiceClient = new(fakeClient)

func newFakeClient() *fakeClient {
	return &fakeClient{
		sendErrCh:    make(chan error),
		recvCh:       make(chan error),
		sendStreamCh: make(chan *discoverypb.DiscoveryRequest),
		sendDeltaCh:  make(chan *discoverypb.DeltaDiscoveryRequest),
		recvStreamCh: make(chan *discoverypb.DiscoveryResponse),
		recvDeltaCh:  make(chan *discoverypb.DeltaDiscoveryResponse),
	}
}

func (f *fakeClient) StreamAggregatedResources(ctx context.Context, opts ...grpc.CallOption) (discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient, error) {
	return &fakeStream{
		OnSend: func(r *discoverypb.DiscoveryRequest) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case f.sendStreamCh <- r:
				return nil
			case err := <-f.sendErrCh:
				return err
			}
		},
		OnRecv: func() (*discoverypb.DiscoveryResponse, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-f.recvStreamCh:
				return r, nil
			case err := <-f.recvCh:
				return nil, err
			}
		},
	}, nil
}

func (f *fakeClient) DeltaAggregatedResources(ctx context.Context, opts ...grpc.CallOption) (discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient, error) {
	return &fakeDelta{
		OnSend: func(r *discoverypb.DeltaDiscoveryRequest) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case f.sendDeltaCh <- r:
				return nil
			case err := <-f.sendErrCh:
				return err
			}
		},
		OnRecv: func() (*discoverypb.DeltaDiscoveryResponse, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case r := <-f.recvDeltaCh:
				return r, nil
			case err := <-f.recvCh:
				return nil, err
			}
		},
	}, nil
}
