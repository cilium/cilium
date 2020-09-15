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

package types

import (
	"io"

	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

// Peer is like hubblePeer.Peer but includes a Conn attribute to reach the
// peer's gRPC API endpoint.
type Peer struct {
	peerTypes.Peer
	Conn ClientConn
}

// ClientConn is an interface that defines the functions clients need to
// perform unary and streaming RPCs. It is implemented by *grpc.ClientConn.
type ClientConn interface {
	// GetState returns the connectivity.State of ClientConn.
	GetState() connectivity.State
	io.Closer
	grpc.ClientConnInterface
}

var _ ClientConn = (*grpc.ClientConn)(nil)

// ClientConnBuilder wraps the ClientConn method.
type ClientConnBuilder interface {
	// ClientConn creates a new ClientConn using target as the address and,
	// optionally, hostname.
	ClientConn(target, hostname string) (ClientConn, error)
}
