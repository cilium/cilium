// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"crypto/tls"
	"io"

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
	// Client builds a new Client.
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

var _ ClientBuilder = (*LocalClientBuilder)(nil)

// LocalClientBuilder is a ClientBuilder that is suitable when the gRPC
// connection to the Peer service is local (typically a Unix Domain Socket).
type LocalClientBuilder struct{}

// Client implements ClientBuilder.Client.
func (b LocalClientBuilder) Client(target string) (Client, error) {
	// The connection is local, so we assume using insecure connection is safe in
	// this context.
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &client{conn, peerpb.NewPeerClient(conn)}, nil
}

var _ ClientBuilder = (*RemoteClientBuilder)(nil)

// RemoteClientBuilder is a ClientBuilder that is suitable when the gRPC
// connection to the Peer service is remote (typically a K8s Service).
type RemoteClientBuilder struct {
	TLSConfig     certloader.ClientConfigBuilder
	TLSServerName string
}

// Client implements the ClientBuilder interface.
func (b RemoteClientBuilder) Client(target string) (Client, error) {
	var opts []grpc.DialOption
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
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, err
	}
	return &client{conn, peerpb.NewPeerClient(conn)}, nil
}
