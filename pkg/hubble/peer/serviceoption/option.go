// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package serviceoption

// Options stores all the configuration values for the peer service.
type Options struct {
	MaxSendBufferSize       int
	WithoutTLSInfo          bool
	AddressFamilyPreference AddressFamilyPreference
}

// Option customizes the peer service's configuration.
type Option func(o *Options)

type AddressFamily uint

const (
	AddressFamilyIPv4 AddressFamily = 4
	AddressFamilyIPv6 AddressFamily = 6
)

type AddressFamilyPreference []AddressFamily

var (
	AddressPreferIPv4 = AddressFamilyPreference{AddressFamilyIPv4, AddressFamilyIPv6}
	AddressPreferIPv6 = AddressFamilyPreference{AddressFamilyIPv6, AddressFamilyIPv4}
)

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

// WithAddressFamilyPreference configures the order in which IP addresses
// will be considered when sending notifications for nodes that have both IPv4
// and IPv6 available.
func WithAddressFamilyPreference(pref AddressFamilyPreference) Option {
	return func(o *Options) {
		o.AddressFamilyPreference = pref
	}
}
