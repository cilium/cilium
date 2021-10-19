// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package ingress

// Options stores all the configurations values for cilium ingress controller.
type Options struct {
	MaxRetries int
}

// DefaultIngressOptions specifies default values for cilium ingress controller.
var DefaultIngressOptions = Options{
	MaxRetries: 10,
}

// Option customizes the configuration of cilium ingress controller
type Option func(o *Options) error

// WithMaxRetries sets the maximum number of retries while processing events
func WithMaxRetries(maxRetries int) Option {
	return func(o *Options) error {
		o.MaxRetries = maxRetries
		return nil
	}
}
