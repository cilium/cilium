// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
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
