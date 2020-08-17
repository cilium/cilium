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

package serviceoption

// Options stores all the configuration values for the peer service.
type Options struct {
	MaxSendBufferSize int
	WithoutTLSInfo    bool
}

// Option customizes then configuration of the peer service.
type Option func(o *Options)

// WithMaxSendBufferSize sets the maximum size of the send buffer. When the
// send buffer is full, for example due to errors in the transport, the server
// disconnects the corresponding client.
// The maximum buffer size should be large enough to accommodate the burst of
// peer change notifications than happens on an initial call where all nodes in
// the cluster are notified as being added.
func WithMaxSendBufferSize(size int) Option {
	return func(o *Options) {
		o.MaxSendBufferSize = size
	}
}

// WithoutTLSInfo configures the service to send peer change notifications
// without TLS information. This implies that TLS is disabled for the Hubble
// gRPC service.
func WithoutTLSInfo() Option {
	return func(o *Options) {
		o.WithoutTLSInfo = true
	}
}
