// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

package testutils

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// FakeGRPCServerStream implements google.golang.org/grpc.ServerStream
// interface for unit tests.
type FakeGRPCServerStream struct {
	OnSetHeader  func(metadata.MD) error
	OnSendHeader func(metadata.MD) error
	OnSetTrailer func(m metadata.MD)
	OnContext    func() context.Context
	OnSendMsg    func(m interface{}) error
	OnRecvMsg    func(m interface{}) error
}

// SetHeader implements grpc.ServerStream.SetHeader.
func (s *FakeGRPCServerStream) SetHeader(m metadata.MD) error {
	if s.OnSetHeader != nil {
		return s.OnSetHeader(m)
	}
	panic("OnSetHeader not set")
}

// SendHeader implements grpc.ServerStream.SendHeader.
func (s *FakeGRPCServerStream) SendHeader(m metadata.MD) error {
	if s.OnSendHeader != nil {
		return s.OnSendHeader(m)
	}
	panic("OnSendHeader not set")
}

// SetTrailer implements grpc.ServerStream.SetTrailer.
func (s *FakeGRPCServerStream) SetTrailer(m metadata.MD) {
	if s.OnSetTrailer != nil {
		s.OnSetTrailer(m)
	}
	panic("OnSetTrailer not set")
}

// Context implements grpc.ServerStream.Context.
func (s *FakeGRPCServerStream) Context() context.Context {
	if s.OnContext != nil {
		return s.OnContext()
	}
	panic("OnContext not set")
}

// SendMsg implements grpc.ServerStream.SendMsg.
func (s *FakeGRPCServerStream) SendMsg(m interface{}) error {
	if s.OnSendMsg != nil {
		return s.OnSendMsg(m)
	}
	panic("OnSendMsg not set")
}

// RecvMsg implements grpc.ServerStream.RecvMsg.
func (s *FakeGRPCServerStream) RecvMsg(m interface{}) error {
	if s.OnRecvMsg != nil {
		return s.OnRecvMsg(m)
	}
	panic("OnRecvMsg not set")
}

// FakeGRPCClientStream implements google.golang.org/grpc.ClientStream
// interface for unit tests.
type FakeGRPCClientStream struct {
	OnHeader    func() (metadata.MD, error)
	OnTrailer   func() metadata.MD
	OnCloseSend func() error
	OnContext   func() context.Context
	OnSendMsg   func(m interface{}) error
	OnRecvMsg   func(m interface{}) error
}

// Header implements grpc.ClientStream.Header.
func (c *FakeGRPCClientStream) Header() (metadata.MD, error) {
	if c.OnHeader != nil {
		return c.OnHeader()
	}
	panic("OnHeader not set")
}

// Trailer implements grpc.ClientStream.Trailer.
func (c *FakeGRPCClientStream) Trailer() metadata.MD {
	if c.OnTrailer != nil {
		return c.OnTrailer()
	}
	panic("OnTrailer not set")
}

// CloseSend implements grpc.ClientStream.CloseSend.
func (c *FakeGRPCClientStream) CloseSend() error {
	if c.OnCloseSend != nil {
		return c.OnCloseSend()
	}
	panic("OnCloseSend not set")
}

// Context implements grpc.ClientStream.Context.
func (c *FakeGRPCClientStream) Context() context.Context {
	if c.OnContext != nil {
		return c.OnContext()
	}
	panic("OnContext not set")
}

// SendMsg implements grpc.ClientStream.SendMsg.
func (c *FakeGRPCClientStream) SendMsg(m interface{}) error {
	if c.OnSendMsg != nil {
		return c.OnSendMsg(m)
	}
	panic("OnSendMsg not set")
}

// RecvMsg implements grpc.ClientStream.RecvMsg.
func (c *FakeGRPCClientStream) RecvMsg(m interface{}) error {
	if c.OnRecvMsg != nil {
		return c.OnRecvMsg(m)
	}
	panic("OnRecvMsg not set")
}
