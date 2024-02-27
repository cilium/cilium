// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"google.golang.org/grpc"
)

type responseType int

const (
	status responseType = iota
	watch
	leaseKeepAlive
	leaseGrant
	invalid
)

type mockClientStream struct {
	grpc.ClientStream
	toClient chan *etcdResponse
}

func newMockClientStream() mockClientStream {
	return mockClientStream{
		toClient: make(chan *etcdResponse),
	}
}

func (c mockClientStream) RecvMsg(msg interface{}) error {
	return nil
}

func (c mockClientStream) Send(resp *etcdResponse) error {
	return nil
}

func newStreamerMock(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return newMockClientStream(), nil
}

func (u unaryResponder) recv() etcdResponse {
	var resp unaryResponse
	switch u.rt {
	case status:
		resp = unaryResponse{&etcdserverpb.StatusResponse{Header: &etcdserverpb.ResponseHeader{ClusterId: u.cid}}}
	case leaseGrant:
		resp = unaryResponse{&etcdserverpb.LeaseGrantResponse{Header: &etcdserverpb.ResponseHeader{ClusterId: u.cid}}}
	case invalid:
		resp = unaryResponse{&etcdserverpb.StatusResponse{}}
	}

	return resp
}

func (s streamResponder) recv() etcdResponse {
	var resp streamResponse
	switch s.rt {
	case watch:
		resp = streamResponse{&etcdserverpb.WatchResponse{Header: &etcdserverpb.ResponseHeader{ClusterId: s.cid}}}
	case leaseKeepAlive:
		resp = streamResponse{&etcdserverpb.LeaseKeepAliveResponse{Header: &etcdserverpb.ResponseHeader{ClusterId: s.cid}}}
	case invalid:
		resp = streamResponse{&etcdserverpb.WatchResponse{}}
	}
	return resp

}

func noopInvoker(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
	return nil
}

type unaryResponder struct {
	rt       responseType
	cid      uint64
	expError error
}

func (u unaryResponder) expectedErr() error {
	return u.expError
}

type unaryResponse struct {
	etcdResponse
}

type streamResponder struct {
	rt       responseType
	cid      uint64
	expError error
}

func (s streamResponder) expectedErr() error {
	return s.expError
}

type streamResponse struct {
	etcdResponse
}

type mockResponder interface {
	recv() etcdResponse
	expectedErr() error
}

var maxId uint64 = 0xFFFFFFFFFFFFFFFF

func TestInterceptors(t *testing.T) {
	tests := []struct {
		name             string
		initialClusterId uint64
		r                []mockResponder
	}{
		{
			name:             "healthy stream responses",
			initialClusterId: 1,
			r: []mockResponder{
				streamResponder{rt: watch, cid: 1, expError: nil},
				streamResponder{rt: watch, cid: 1, expError: nil},
				streamResponder{rt: watch, cid: 1, expError: nil},
			},
		},
		{
			name:             "healthy unary responses",
			initialClusterId: 1,
			r: []mockResponder{
				unaryResponder{rt: leaseGrant, cid: 1, expError: nil},
				unaryResponder{rt: status, cid: 1, expError: nil},
			},
		},
		{
			name:             "healthy stream and unary responses",
			initialClusterId: maxId,
			r: []mockResponder{
				unaryResponder{rt: leaseGrant, cid: maxId, expError: nil},
				unaryResponder{rt: status, cid: maxId, expError: nil},
				streamResponder{rt: watch, cid: maxId, expError: nil},
				unaryResponder{rt: status, cid: maxId, expError: nil},
				streamResponder{rt: watch, cid: maxId, expError: nil},
			},
		},
		{
			name:             "watch response from another cluster",
			initialClusterId: 1,
			r: []mockResponder{
				streamResponder{rt: watch, cid: 1, expError: nil},
				streamResponder{rt: watch, cid: 2, expError: ErrClusterIDChanged},
				streamResponder{rt: watch, cid: 1, expError: nil},
			},
		},
		{
			name:             "status response from another cluster",
			initialClusterId: 1,
			r: []mockResponder{
				streamResponder{rt: watch, cid: 1, expError: nil},
				unaryResponder{rt: status, cid: maxId, expError: ErrClusterIDChanged},
				streamResponder{rt: watch, cid: 1, expError: nil},
			},
		},
		{
			name:             "receive an invalid response with no header",
			initialClusterId: 1,
			r: []mockResponder{
				streamResponder{rt: leaseKeepAlive, cid: 1, expError: nil},
				streamResponder{rt: invalid, cid: 0, expError: ErrEtcdInvalidResponse},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cl := newClusterLock()
			checkForError := func() error {
				select {
				case err := <-cl.errors:
					return err
				default:
					return nil
				}
			}

			si := newStreamInterceptor(cl)
			desc := &grpc.StreamDesc{
				StreamName:    "test",
				Handler:       nil,
				ServerStreams: true,
				ClientStreams: true,
			}

			cc := &grpc.ClientConn{}

			stream, err := si(ctx, desc, cc, "test", newStreamerMock)
			require.NoError(t, err)

			unaryRecvMsg := newUnaryInterceptor(cl)
			for _, responder := range tt.r {

				switch response := responder.recv().(type) {
				case unaryResponse:
					unaryRecvMsg(ctx, "test", nil, response, cc, noopInvoker)
				case streamResponse:
					stream.RecvMsg(responder.recv())
				}
				require.ErrorIs(t, checkForError(), responder.expectedErr())
				require.Equal(t, tt.initialClusterId, cl.etcdClusterID.Load())
			}
		})
	}

}
