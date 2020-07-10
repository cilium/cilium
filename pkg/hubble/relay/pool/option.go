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

	"github.com/cilium/cilium/pkg/defaults"
	hubblePeer "github.com/cilium/cilium/pkg/hubble/peer"
)

// DefaultOptions is the reference point for default values.
var DefaultOptions = Options{
	PeerClientBuilder: hubblePeer.LocalClientBuilder{
		LocalAddress: "unix://" + defaults.HubbleSockPath,
		DialTimeout:  5 * time.Second,
	},
	DialTimeout:  5 * time.Second,
	RetryTimeout: 30 * time.Second,
}

// Option customizes the configuration of the Manager.
type Option func(o *Options) error

// Options stores all the configuration values for peer manager.
type Options struct {
	PeerClientBuilder hubblePeer.ClientBuilder
	DialTimeout       time.Duration
	RetryTimeout      time.Duration
	Debug             bool
}

// WithPeerClientBuilder sets the ClientBuilder that is used to create new Peer
// service clients.
func WithPeerClientBuilder(b hubblePeer.ClientBuilder) Option {
	return func(o *Options) error {
		o.PeerClientBuilder = b
		return nil
	}
}

// WithDialTimeout sets the dial timeout that is used when establishing a
// connection.
func WithDialTimeout(t time.Duration) Option {
	return func(o *Options) error {
		o.DialTimeout = t
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

// WithDebug enables debug mode.
func WithDebug() Option {
	return func(o *Options) error {
		o.Debug = true
		return nil
	}
}
