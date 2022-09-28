// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package ingress

// Options stores all the configurations values for cilium ingress controller.
type Options struct {
	MaxRetries           int
	EnforcedHTTPS        bool
	EnabledSecretsSync   bool
	SecretsNamespace     string
	LBAnnotationPrefixes []string
	SharedLBServiceName  string
	CiliumNamespace      string
}

// DefaultIngressOptions specifies default values for cilium ingress controller.
var DefaultIngressOptions = Options{
	MaxRetries:           10,
	EnforcedHTTPS:        true,
	EnabledSecretsSync:   true,
	LBAnnotationPrefixes: []string{},
	SharedLBServiceName:  "cilium-ingress",
	CiliumNamespace:      "kube-system",
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

// WithHTTPSEnforced specifies if https enforcement should be done or not
func WithHTTPSEnforced(enforcedHTTPS bool) Option {
	return func(o *Options) error {
		o.EnforcedHTTPS = enforcedHTTPS
		return nil
	}
}

// WithSecretsSyncEnabled specifies if secrets syncs process should be done or not
func WithSecretsSyncEnabled(enabledSecretsSync bool) Option {
	return func(o *Options) error {
		o.EnabledSecretsSync = enabledSecretsSync
		return nil
	}
}

// WithSecretsNamespace configures destination namespace for syncing all TLS secrets across namespaces.
func WithSecretsNamespace(secretsNamespace string) Option {
	return func(o *Options) error {
		o.SecretsNamespace = secretsNamespace
		return nil
	}
}

// WithLBAnnotationPrefixes configures LB annotations to be used for LB service
func WithLBAnnotationPrefixes(lbAnnotationPrefixes []string) Option {
	return func(o *Options) error {
		o.LBAnnotationPrefixes = lbAnnotationPrefixes
		return nil
	}
}

// WithSharedLBServiceName configures the name of the shared LB service
func WithSharedLBServiceName(sharedLBServiceName string) Option {
	return func(o *Options) error {
		o.SharedLBServiceName = sharedLBServiceName
		return nil
	}
}

// WithCiliumNamespace configures the namespace of cilium
func WithCiliumNamespace(ciliumNamespace string) Option {
	return func(o *Options) error {
		o.CiliumNamespace = ciliumNamespace
		return nil
	}
}
