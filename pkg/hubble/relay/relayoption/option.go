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
	"fmt"
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

	BufferMaxLen           int
	BufferDrainTimeout     time.Duration
	ErrorAggregationWindow time.Duration
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

// WithBufferMaxLen sets the maximum number of flows that can be buffered
// before being sent to the client. This affects operations such as flows
// sorting. The provided value must be greater than 0 and is to be understood
// per client request. Therefore, it is advised to keep the value moderate (a
// value between 30 and 100 should constitute a good choice in most cases).
func WithBufferMaxLen(i int) Option {
	return func(o *Options) error {
		if i <= 0 {
			return fmt.Errorf("value for BufferMaxLen must be greater than 0: %d", i)
		}
		o.BufferMaxLen = i
		return nil
	}
}

// WithBufferDrainTimeout sets the buffer drain timeout value. For flows
// requests where the total number of flows cannot be determined (typically for
// flows requests in follow mode), a flow is taken out of the buffer and sent
// to the client after duration d if the buffer is not full. This value must be
// greater than 0. Setting this value too low would render the flows sorting
// operation ineffective. A value between 500 milliseconds and 3 seconds should
// be constitute a good choice in most cases.
func WithBufferDrainTimeout(d time.Duration) Option {
	return func(o *Options) error {
		if d <= 0 {
			return fmt.Errorf("value for BufferDrainTimeout must be greater than 0: %d", d)
		}
		o.BufferDrainTimeout = d
		return nil
	}
}

// WithErrorAggregationWindow sets a time window during which errors with the
// same error message are coalesced. The aggregated error is forwarded to the
// downstream consumer either when the window expires or when a new, different
// error occurs (whichever happens first)
func WithErrorAggregationWindow(d time.Duration) Option {
	return func(o *Options) error {
		if d <= 0 {
			return fmt.Errorf("value for ErrorAggregationWindow must be greater than 0: %d", d)
		}
		o.ErrorAggregationWindow = d
		return nil
	}
}
