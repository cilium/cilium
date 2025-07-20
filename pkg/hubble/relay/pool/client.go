// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	hubbleopts "github.com/cilium/cilium/pkg/hubble/server/serveroption"
	"github.com/cilium/cilium/pkg/lock"
)

var _ poolTypes.ClientConnBuilder = (*GRPCClientConnBuilder)(nil)

// GRPCClientConnBuilder is a generic ClientConnBuilder implementation.
type GRPCClientConnBuilder struct {
	// Options is a set of grpc.DialOption to be used when creating a new
	// connection.
	Options []grpc.DialOption

	// TLSConfig is used to build transport credentials for the connection.
	// If not provided, insecure credentials are added to Options before creating
	// a new ClientConn.
	TLSConfig certloader.ClientConfigBuilder
}

// ClientConn implements ClientConnBuilder.ClientConn.
func (b GRPCClientConnBuilder) ClientConn(target, hostname string) (poolTypes.ClientConn, error) {
	// Ensure that the hostname (used as ServerName) information is given when
	// Relay is configured with mTLS, and empty otherwise. We do this to report
	// a mTLS misconfiguration between Hubble and Relay as early as possible.
	switch {
	case b.TLSConfig != nil && hostname == "":
		return nil, fmt.Errorf("missing TLS ServerName for %s", target)
	case b.TLSConfig == nil && hostname != "":
		return nil, fmt.Errorf("unexpected TLS ServerName %s for %s", hostname, target)
	}

	opts := make([]grpc.DialOption, len(b.Options))
	copy(opts, b.Options)

	if b.TLSConfig == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// NOTE: gosec is unable to resolve the constant and warns about "TLS
		// MinVersion too low".
		baseConf := &tls.Config{ //nolint:gosec
			ServerName: hostname,
			MinVersion: hubbleopts.MinTLSVersion,
		}
		opts = append(opts, grpc.WithTransportCredentials(
			&grpcTLSCredentialsWrapper{
				TransportCredentials: credentials.NewTLS(b.TLSConfig.ClientConfig(baseConf)),
				baseConf:             baseConf,
				TLSConfig:            b.TLSConfig,
			},
		))
	}
	return grpc.NewClient(target, opts...)
}

var _ credentials.TransportCredentials = (*grpcTLSCredentialsWrapper)(nil)

// grpcTLSCredentialsWrapper wraps gRPC TransportCredentials and fetches the
// newest TLS configuration from certloader whenever a new TLS connection
// is established.
//
// A gRPC ClientConn will call ClientHandshake whenever it tries to establish
// a new TLS connection.
//
// Wrapping the ClientHandshake and fetching the updated certificate and CA
// allows us to transparently reload certificates when they change.
type grpcTLSCredentialsWrapper struct {
	credentials.TransportCredentials

	mu        lock.Mutex
	baseConf  *tls.Config
	TLSConfig certloader.ClientConfigBuilder
}

// ClientHandshake implements credentials.TransportCredentials.
func (w *grpcTLSCredentialsWrapper) ClientHandshake(ctx context.Context, addr string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.TransportCredentials = credentials.NewTLS(w.TLSConfig.ClientConfig(w.baseConf))
	return w.TransportCredentials.ClientHandshake(ctx, addr, conn)
}

// Clone implements credentials.TransportCredentials.
func (w *grpcTLSCredentialsWrapper) Clone() credentials.TransportCredentials {
	w.mu.Lock()
	defer w.mu.Unlock()
	return &grpcTLSCredentialsWrapper{
		baseConf:             w.baseConf.Clone(),
		TransportCredentials: w.TransportCredentials.Clone(),
		TLSConfig:            w.TLSConfig,
	}
}
