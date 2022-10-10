// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"k8s.io/client-go/util/workqueue"
)

type Option func(*options)

// WithRateLimiter sets the rate limiter to use with the resource.
func WithRateLimiter(newLimiter func() workqueue.RateLimiter) Option {
	return func(o *options) { o.rateLimiter = newLimiter }
}

// WithErrorHandler sets the function that decides how to handle
// an error from event processing.
func WithErrorHandler(h ErrorHandler) Option {
	return func(o *options) { o.errorHandler = h }
}

type options struct {
	rateLimiter  func() workqueue.RateLimiter
	errorHandler ErrorHandler
}

func defaultOptions() options {
	return options{
		rateLimiter: func() workqueue.RateLimiter {
			return workqueue.DefaultControllerRateLimiter()
		},
		errorHandler: AlwaysRetry,
	}
}
