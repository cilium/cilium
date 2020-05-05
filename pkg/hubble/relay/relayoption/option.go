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

package relayoption

import (
	"strings"
	"time"
)

// Options stores all the configuration values for the hubble-relay server.
type Options struct {
	HubbleTarget  string
	DialTimeout   time.Duration
	RetryTimeout  time.Duration
	ListenAddress string
	Debug         bool
}

// Option customizes the configuration of the hubble-relay server.
type Option func(o *Options) error

// WithHubbleTarget sets the URL of the local hubble instance to connect to.
// This target MUST implement the Peer service.
func WithHubbleTarget(t string) Option {
	return func(o *Options) error {
		if !strings.HasPrefix(t, "unix://") {
			t = "unix://" + t
		}
		o.HubbleTarget = t
		return nil
	}
}

// WithDialTimeout sets the dial timeout that is used when establishing a
// connection to a hubble peer.
func WithDialTimeout(t time.Duration) Option {
	return func(o *Options) error {
		o.DialTimeout = t
		return nil
	}
}

// WithRetryTimeout sets the duration to wait before attempting to re-connect
// to a hubble peer when the connection is lost.
func WithRetryTimeout(t time.Duration) Option {
	return func(o *Options) error {
		o.RetryTimeout = t
		return nil
	}
}

// WithListenAddress sets the listen address for the hubble-relay server.
func WithListenAddress(a string) Option {
	return func(o *Options) error {
		o.ListenAddress = a
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
