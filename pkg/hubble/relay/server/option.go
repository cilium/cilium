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
	"crypto/tls"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/hubble/relay/observer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

// MinTLSVersion defines the minimum TLS version clients are expected to
// support in order to establish a connection to the hubble-relay server.
const MinTLSVersion = tls.VersionTLS13

// options stores all the configuration values for the hubble-relay server.
type options struct {
	hubbleTarget    string
	dialTimeout     time.Duration
	retryTimeout    time.Duration
	listenAddress   string
	log             logrus.FieldLogger
	serverTLSConfig certloader.ServerConfigBuilder
	insecureServer  bool
	clientTLSConfig certloader.ClientConfigBuilder
	insecureClient  bool
	observerOptions []observer.Option
}

// defaultOptions is the reference point for default values.
var defaultOptions = options{
	hubbleTarget:  defaults.HubbleTarget,
	dialTimeout:   defaults.DialTimeout,
	retryTimeout:  defaults.RetryTimeout,
	listenAddress: defaults.ListenAddress,
	log:           logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay"),
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

// WithLogger set the logger used by hubble-relay.
func WithLogger(log logrus.FieldLogger) Option {
	return func(o *options) error {
		o.log = log
		return nil
	}
}

// WithServerTLS sets the transport credentials for the server based on TLS.
func WithServerTLS(cfg certloader.ServerConfigBuilder) Option {
	return func(o *options) error {
		o.serverTLSConfig = cfg
		return nil
	}
}

// WithInsecureServer disables transport security. Transport security is
// required for the server unless WithInsecureServer is set (not recommended).
func WithInsecureServer() Option {
	return func(o *options) error {
		o.insecureServer = true
		return nil
	}
}

// WithClientTLS sets the transport credentials for connecting to peers based
// on the provided TLS configuration.
func WithClientTLS(cfg certloader.ClientConfigBuilder) Option {
	return func(o *options) error {
		o.clientTLSConfig = cfg
		return nil
	}
}

// WithInsecureClient disables transport security for connection to Hubble
// server instances. Transport security is required to WithInsecureClient is
// set (not recommended).
func WithInsecureClient() Option {
	return func(o *options) error {
		o.insecureClient = true
		return nil
	}
}
