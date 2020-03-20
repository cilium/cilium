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

package proxy

import (
	"strings"
	"time"
)

// Options stores all the configuration values for the hubble proxy server.
type Options struct {
	HubbleTarget  string
	DialTimeout   time.Duration
	ListenAddress string
}

// Option customizes the configuration of the hubble proxy server.
type Option func(o *Options) error

// WithHubbleTarget sets the URL of the hubble server instance to connect to.
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
// connection to the hubble server instance that is being proxied.
func WithDialTimeout(t time.Duration) Option {
	return func(o *Options) error {
		o.DialTimeout = t
		return nil
	}
}

// WithListenAddress sets the listen address for the hubble proxy server.
func WithListenAddress(a string) Option {
	return func(o *Options) error {
		o.ListenAddress = a
		return nil
	}
}
