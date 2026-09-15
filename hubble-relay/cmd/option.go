// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "github.com/cilium/cilium/hubble-relay/cmd/serve"

// cmdOptions collects the optional integrations used while constructing the
// root command. Keeping serve extensions here lets downstream binaries compose
// Relay without changing the default command behavior.
type cmdOptions struct {
	// serveExtensions preserves the caller-supplied order used for flag
	// registration, configuration, server options, and reverse cleanup.
	serveExtensions []serve.Extension
}

// Option configures the Hubble Relay command before its subcommands are built.
type Option func(*cmdOptions)

// WithServeExtensions adds extensions to the serve command. Extensions are
// registered and configured in the supplied order; resources returned by them
// are released in reverse order by the serve command.
func WithServeExtensions(extensions ...serve.Extension) Option {
	return func(opts *cmdOptions) {
		opts.serveExtensions = append(opts.serveExtensions, extensions...)
	}
}
