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

package server

import (
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/observer"
)

// options stores all the configuration values for the hubble-relay server.
type options struct {
	hubbleTarget    string
	dialTimeout     time.Duration
	retryTimeout    time.Duration
	listenAddress   string
	debug           bool
	observerOptions []observer.Option
}

// defaultOptions is the reference point for default values.
var defaultOptions = options{
	hubbleTarget:  defaults.HubbleTarget,
	dialTimeout:   defaults.DialTimeout,
	retryTimeout:  defaults.RetryTimeout,
	listenAddress: defaults.ListenAddress,
}

// Option customizes the configuration of the hubble-relay server.
type Option func(o *options) error

// WithHubbleTarget sets the URL of the local hubble instance to connect to.
// This target MUST implement the Peer service.
func WithHubbleTarget(t string) Option {
	return func(o *options) error {
		if !strings.HasPrefix(t, "unix://") {
			t = "unix://" + t
		}
		o.hubbleTarget = t
		return nil
	}
}

// WithDialTimeout sets the dial timeout that is used when establishing a
// connection to a hubble peer.
func WithDialTimeout(t time.Duration) Option {
	return func(o *options) error {
		o.dialTimeout = t
		return nil
	}
}

// WithRetryTimeout sets the duration to wait before attempting to re-connect
// to a hubble peer when the connection is lost.
func WithRetryTimeout(t time.Duration) Option {
	return func(o *options) error {
		o.retryTimeout = t
		return nil
	}
}

// WithListenAddress sets the listen address for the hubble-relay server.
func WithListenAddress(a string) Option {
	return func(o *options) error {
		o.listenAddress = a
		return nil
	}
}

// WithDebug enables debug mode.
func WithDebug() Option {
	return func(o *options) error {
		o.debug = true
		return nil
	}
}

// WithSortBufferMaxLen sets the maximum number of flows that can be buffered
// for sorting before being sent to the client. The provided value must be
// greater than 0 and is to be understood per client request. Therefore, it is
// advised to keep the value moderate (a value between 30 and 100 should
// constitute a good choice in most cases).
func WithSortBufferMaxLen(i int) Option {
	return func(o *options) error {
		o.observerOptions = append(o.observerOptions, observer.WithSortBufferMaxLen(i))
		return nil
	}
}

// WithSortBufferDrainTimeout sets the sort buffer drain timeout value. For
// flows requests where the total number of flows cannot be determined
// (typically for flows requests in follow mode), a flow is taken out of the
// buffer and sent to the client after duration d if the buffer is not full.
// This value must be greater than 0. Setting this value too low would render
// the flows sorting operation ineffective. A value between 500 milliseconds
// and 3 seconds should be constitute a good choice in most cases.
func WithSortBufferDrainTimeout(d time.Duration) Option {
	return func(o *options) error {
		o.observerOptions = append(o.observerOptions, observer.WithSortBufferDrainTimeout(d))
		return nil
	}
}

// WithErrorAggregationWindow sets a time window during which errors with the
// same error message are coalesced. The aggregated error is forwarded to the
// downstream consumer either when the window expires or when a new, different
// error occurs (whichever happens first)
func WithErrorAggregationWindow(d time.Duration) Option {
	return func(o *options) error {
		o.observerOptions = append(o.observerOptions, observer.WithErrorAggregationWindow(d))
		return nil
	}
}
