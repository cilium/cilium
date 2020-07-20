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
	"context"
	"io"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"

	"google.golang.org/grpc"
)

// Client defines an interface that Peer service client should implement.
type Client interface {
	peerpb.PeerClient
	io.Closer
}

// ClientBuilder creates a new Client.
type ClientBuilder interface {
	// Client builds a new Client that connects to the given target.
	Client(target string) (Client, error)
}

type client struct {
	conn *grpc.ClientConn
	peerpb.PeerClient
}

func (c *client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// LocalClientBuilder is a ClientBuilder that is suitable when the gRPC
// connection to the Peer service is local (typically a Unix Domain Socket).
type LocalClientBuilder struct {
	DialTimeout time.Duration
}

// Client implements ClientBuilder.Client.
func (b LocalClientBuilder) Client(target string) (Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.DialTimeout)
	defer cancel()
	// the connection is local so we assume WithInsecure() is safe in this context
	conn, err := grpc.DialContext(ctx, target, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, err
	}
	return &client{conn, peerpb.NewPeerClient(conn)}, nil
}
