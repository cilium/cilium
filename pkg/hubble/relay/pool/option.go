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
	"time"

	"github.com/cilium/cilium/pkg/backoff"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// defaultOptions is the reference point for default values.
var defaultOptions = options{
	peerServiceAddress: defaults.HubbleTarget,
	peerClientBuilder: peerTypes.LocalClientBuilder{
		DialTimeout: defaults.DialTimeout,
	},
	clientConnBuilder: GRPCClientConnBuilder{
		DialTimeout: defaults.DialTimeout,
		Options: []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithBlock(),
			grpc.FailOnNonTempDialError(true),
			// TODO: uncomment the line below once grpc-go is >= v1.30.0
			// currently blocked on v1.29.1, see the following PR for details
			// https://github.com/cilium/cilium/pull/13405
			// grpc.WithReturnConnectionError(),
		},
	},
	backoff: &backoff.Exponential{
		Min:    10 * time.Second,
		Max:    90 * time.Minute,
		Factor: 2.0,
	},
	connCheckInterval: 2 * time.Minute,
	retryTimeout:      defaults.RetryTimeout,
	log:               logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay"),
}

// Option customizes the configuration of the Manager.
type Option func(o *options) error

// options stores all the configuration values for peer manager.
type options struct {
	peerServiceAddress string
	peerClientBuilder  peerTypes.ClientBuilder
	clientConnBuilder  poolTypes.ClientConnBuilder
	backoff            BackoffDuration
	connCheckInterval  time.Duration
	retryTimeout       time.Duration
	log                logrus.FieldLogger
}

// WithPeerServiceAddress sets the address of the peer gRPC service.
func WithPeerServiceAddress(a string) Option {
	return func(o *options) error {
		o.peerServiceAddress = a
		return nil
	}
}

// WithPeerClientBuilder sets the ClientBuilder that is used to create new Peer
// service clients.
func WithPeerClientBuilder(b peerTypes.ClientBuilder) Option {
	return func(o *options) error {
		o.peerClientBuilder = b
		return nil
	}
}

// WithClientConnBuilder sets the GRPCClientConnBuilder that is used to create
// new gRPC connections to peers.
func WithClientConnBuilder(b poolTypes.ClientConnBuilder) Option {
	return func(o *options) error {
		o.clientConnBuilder = b
		return nil
	}
}

// WithBackoff sets the backoff between after a failed connection attempt.
func WithBackoff(b BackoffDuration) Option {
	return func(o *options) error {
		o.backoff = b
		return nil
	}
}

// WithConnCheckInterval sets the time interval between peer connections health
// checks.
func WithConnCheckInterval(i time.Duration) Option {
	return func(o *options) error {
		o.connCheckInterval = i
		return nil
	}
}

// WithRetryTimeout sets the duration to wait before attempting to re-connect
// to the peer gRPC service.
func WithRetryTimeout(t time.Duration) Option {
	return func(o *options) error {
		o.retryTimeout = t
		return nil
	}
}

// WithLogger sets the logger to use for logging.
func WithLogger(l logrus.FieldLogger) Option {
	return func(o *options) error {
		o.log = l
		return nil
	}
}
