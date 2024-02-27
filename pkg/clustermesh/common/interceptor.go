// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"google.golang.org/grpc"
)

var (
	ErrClusterIDChanged    = errors.New("etcd cluster ID has changed")
	ErrEtcdInvalidResponse = errors.New("received an invalid etcd response")
)

// newUnaryInterceptor returns a new unary client interceptor that validates the
// cluster ID of any received etcd responses.
func newUnaryInterceptor(cl *clusterLock) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if err := invoker(ctx, method, req, reply, cc, opts...); err != nil {
			return err
		}
		return validateReply(cl, reply)
	}
}

// newStreamInterceptor returns a new stream client interceptor that validates
// the cluster ID of any received etcd responses.
func newStreamInterceptor(cl *clusterLock) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		return &wrappedClientStream{
			ClientStream: s,
			clusterLock:  cl,
		}, nil
	}
}

// wrappedClientStream is a wrapper around a grpc.ClientStream that adds
// validation for the etcd cluster ID
type wrappedClientStream struct {
	grpc.ClientStream
	clusterLock *clusterLock
}

// RecvMsg implements the grpc.ClientStream interface, adding validation for the etcd cluster ID
func (w *wrappedClientStream) RecvMsg(m interface{}) error {
	if err := w.ClientStream.RecvMsg(m); err != nil {
		return err
	}

	return validateReply(w.clusterLock, m)
}

type etcdResponse interface {
	GetHeader() *etcdserverpb.ResponseHeader
}

func validateReply(cl *clusterLock, reply any) error {
	resp, ok := reply.(etcdResponse)
	if !ok || resp.GetHeader() == nil {
		select {
		case cl.errors <- ErrEtcdInvalidResponse:
		default:
		}
		return ErrEtcdInvalidResponse
	}

	if err := cl.validateClusterId(resp.GetHeader().ClusterId); err != nil {
		select {
		case cl.errors <- err:
		default:
		}
		return err
	}
	return nil
}

// clusterLock is a wrapper around an atomic uint64 that can only be set once. It
// provides validation for an etcd connection to ensure that it is only used
// for the same etcd cluster it was initially connected to. This is to prevent
// accidentally connecting to the wrong cluster in a high availability
// configuration utilizing mutiple active clusters.
type clusterLock struct {
	etcdClusterID atomic.Uint64
	errors        chan error
}

func newClusterLock() *clusterLock {
	return &clusterLock{
		etcdClusterID: atomic.Uint64{},
		errors:        make(chan error, 1),
	}
}

func (c *clusterLock) validateClusterId(clusterId uint64) error {
	// If the cluster ID has not been set, set it to the received cluster ID
	c.etcdClusterID.CompareAndSwap(0, clusterId)

	if clusterId != c.etcdClusterID.Load() {
		return fmt.Errorf("%w: expected %d, got %d", ErrClusterIDChanged, c.etcdClusterID.Load(), clusterId)
	}
	return nil
}
