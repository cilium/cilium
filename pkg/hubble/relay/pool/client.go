// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	hubbleopts "github.com/cilium/cilium/pkg/hubble/server/serveroption"
)

// GRPCClientConnBuilder is a generic ClientConnBuilder implementation.
type GRPCClientConnBuilder struct {
	// DialTimeout specifies the timeout used when establishing a new
	// connection.
	DialTimeout time.Duration
	// Options is a set of grpc.DialOption to be used when creating a new
	// connection.
	Options []grpc.DialOption

	// TLSConfig is used to build transport credentials for the connection.
	// If not provided, grpc.WithInsecure() is added to Options before creating
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

	ctx, cancel := context.WithTimeout(context.Background(), b.DialTimeout)
	defer cancel()
	opts := make([]grpc.DialOption, len(b.Options))
	copy(opts, b.Options)

	if b.TLSConfig == nil {
		opts = append(opts, grpc.WithInsecure())
	} else {
		// NOTE: gosec is unable to resolve the constant and warns about "TLS
		// MinVersion too low".
		tlsConfig := b.TLSConfig.ClientConfig(&tls.Config{ //nolint:gosec
			ServerName: hostname,
			MinVersion: hubbleopts.MinTLSVersion,
		})
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	return grpc.DialContext(ctx, target, opts...)
}
