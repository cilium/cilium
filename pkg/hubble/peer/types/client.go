// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/crypto/certloader"
	hubbleopts "github.com/cilium/cilium/pkg/hubble/server/serveroption"
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

// RemoteClientBuilder is a ClientBuilder that is suitable when the gRPC
// connection to the Peer service is remote (typically a K8s Service).
type RemoteClientBuilder struct {
	DialTimeout   time.Duration
	TLSConfig     certloader.ClientConfigBuilder
	TLSServerName string
}

// Client implements ClientBuilder.Client.
func (b RemoteClientBuilder) Client(target string) (Client, error) {
	opts := []grpc.DialOption{grpc.WithBlock()}
	if b.TLSConfig == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// NOTE: gosec is unable to resolve the constant and warns about "TLS
		// MinVersion too low".
		tlsConfig := b.TLSConfig.ClientConfig(&tls.Config{ //nolint:gosec
			ServerName: b.TLSServerName,
			MinVersion: hubbleopts.MinTLSVersion,
		})
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.DialTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, target, opts...)
	if err != nil {
		return nil, err
	}
	return &client{conn, peerpb.NewPeerClient(conn)}, nil
}
