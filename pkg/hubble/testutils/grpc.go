// Copyright 2019 Authors of Hubble
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
package testutils

import (
	"context"

	"google.golang.org/grpc/metadata"
)

type FakeGRPCServerStream struct {
	OnSetHeader  func(metadata.MD) error
	OnSendHeader func(metadata.MD) error
	OnSetTrailer func(m metadata.MD)
	OnContext    func() context.Context
	OnSendMsg    func(m interface{}) error
	OnRecvMsg    func(m interface{}) error
}

func (s *FakeGRPCServerStream) SetHeader(m metadata.MD) error {
	if s.OnSetHeader != nil {
		return s.OnSetHeader(m)
	}
	panic("OnSetHeader not set")
}

func (s *FakeGRPCServerStream) SendHeader(m metadata.MD) error {
	if s.OnSendHeader != nil {
		return s.OnSendHeader(m)
	}
	panic("OnSendHeader not set")
}

func (s *FakeGRPCServerStream) SetTrailer(m metadata.MD) {
	if s.OnSetTrailer != nil {
		s.OnSetTrailer(m)
	}
	panic("OnSetTrailer not set")
}

func (s *FakeGRPCServerStream) Context() context.Context {
	if s.OnContext != nil {
		return s.OnContext()
	}
	panic("OnContext not set")
}

func (s *FakeGRPCServerStream) SendMsg(m interface{}) error {
	if s.OnSendMsg != nil {
		return s.OnSendMsg(m)
	}
	panic("OnSendMsg not set")
}

func (s *FakeGRPCServerStream) RecvMsg(m interface{}) error {
	if s.OnRecvMsg != nil {
		return s.OnRecvMsg(m)
	}
	panic("OnRecvMsg not set")
}
