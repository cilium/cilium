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

package pool

import (
	"context"
	"crypto/tls"
	"time"

	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	TLSConfig *tls.Config
}

// ClientConn implements ClientConnBuilder.ClientConn.
func (b GRPCClientConnBuilder) ClientConn(target, hostname string) (poolTypes.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.DialTimeout)
	defer cancel()
	opts := make([]grpc.DialOption, len(b.Options))
	copy(opts, b.Options)

	switch b.TLSConfig {
	case nil:
		opts = append(opts, grpc.WithInsecure())
	default:
		tlsConfig := b.TLSConfig.Clone()
		tlsConfig.ServerName = hostname
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}
	return grpc.DialContext(ctx, target, opts...)
}
