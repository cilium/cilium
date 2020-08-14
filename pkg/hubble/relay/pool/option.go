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
	"github.com/cilium/cilium/pkg/defaults"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// DefaultOptions is the reference point for default values.
var DefaultOptions = Options{
	PeerServiceAddress: "unix://" + defaults.HubbleSockPath,
	PeerClientBuilder: peerTypes.LocalClientBuilder{
		DialTimeout: 5 * time.Second,
	},
	ClientConnBuilder: GRPCClientConnBuilder{
		DialTimeout: 5 * time.Second,
		Options: []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithBlock(),
		},
	},
	Backoff: &backoff.Exponential{
		Min:    10 * time.Second,
		Max:    90 * time.Minute,
		Factor: 2.0,
	},
	ConnCheckInterval: 2 * time.Minute,
	RetryTimeout:      30 * time.Second,
	Log:               logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay"),
}

// Option customizes the configuration of the Manager.
type Option func(o *Options) error

// Options stores all the configuration values for peer manager.
type Options struct {
	PeerServiceAddress string
	PeerClientBuilder  peerTypes.ClientBuilder
	ClientConnBuilder  ClientConnBuilder
	Backoff            BackoffDuration
	ConnCheckInterval  time.Duration
	RetryTimeout       time.Duration
	Log                logrus.FieldLogger
}

// WithPeerServiceAddress sets the address of the peer gRPC service.
func WithPeerServiceAddress(a string) Option {
	return func(o *Options) error {
		o.PeerServiceAddress = a
		return nil
	}
}

// WithPeerClientBuilder sets the ClientBuilder that is used to create new Peer
// service clients.
func WithPeerClientBuilder(b peerTypes.ClientBuilder) Option {
	return func(o *Options) error {
		o.PeerClientBuilder = b
		return nil
	}
}

// WithClientConnBuilder sets the GRPCClientConnBuilder that is used to create
// new gRPC connections to peers.
func WithClientConnBuilder(b ClientConnBuilder) Option {
	return func(o *Options) error {
		o.ClientConnBuilder = b
		return nil
	}
}

// WithBackoff sets the backoff between after a failed connection attempt.
func WithBackoff(b BackoffDuration) Option {
	return func(o *Options) error {
		o.Backoff = b
		return nil
	}
}

// WithConnCheckInterval sets the time interval between peer connections health
// checks.
func WithConnCheckInterval(i time.Duration) Option {
	return func(o *Options) error {
		o.ConnCheckInterval = i
		return nil
	}
}

// WithRetryTimeout sets the duration to wait before attempting to re-connect
// to the peer gRPC service.
func WithRetryTimeout(t time.Duration) Option {
	return func(o *Options) error {
		o.RetryTimeout = t
		return nil
	}
}

// WithLogger sets the logger to use for logging.
func WithLogger(l logrus.FieldLogger) Option {
	return func(o *Options) error {
		o.Log = l
		return nil
	}
}
