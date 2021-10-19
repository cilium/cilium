// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package ingress

// Options stores all the configurations values for cilium ingress controller.
type Options struct {
	Enabled    bool
	MaxRetries int
}

// DefaultIngressOptions specifies default values for Hubble exporter options.
var DefaultIngressOptions = Options{
	Enabled:    false,
	MaxRetries: 10,
}

// Option customizes the configuration of the hubble server.
type Option func(o *Options) error

// WithEnabled sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithEnabled() Option {
	return func(o *Options) error {
		o.Enabled = true
		return nil
	}
}

// WithMaxRetries sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithMaxRetries(maxRetries int) Option {
	return func(o *Options) error {
		o.MaxRetries = maxRetries
		return nil
	}
}
