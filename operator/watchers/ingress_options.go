// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package watchers

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// IngressOptions stores all the configurations values for cilium ingress controller.
type IngressOptions struct {
	Enabled    bool
	Logger     logrus.FieldLogger
	MaxRetries int
}

// DefaultIngressOptions specifies default values for Hubble exporter options.
var DefaultIngressOptions = IngressOptions{
	Enabled:    false,
	Logger:     log.Logger.WithField(logfields.LogSubsys, IngressSubsys),
	MaxRetries: 10,
}

// IngressOption customizes the configuration of the hubble server.
type IngressOption func(o *IngressOptions) error

// WithEnabled sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithEnabled() IngressOption {
	return func(o *IngressOptions) error {
		o.Enabled = true
		return nil
	}
}

// WithLogger sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithLogger(logger logrus.FieldLogger) IngressOption {
	return func(o *IngressOptions) error {
		o.Logger = logger
		return nil
	}
}

// WithMaxRetries sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithMaxRetries(maxRetries int) IngressOption {
	return func(o *IngressOptions) error {
		o.MaxRetries = maxRetries
		return nil
	}
}
