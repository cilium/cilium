// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

// Shutdowner provides Shutdown(), which is a way to trigger stop for hive.
//
// To shut down with an error, call Shutdown with ShutdownWithError(err).
// This error will be returned from Run().
type Shutdowner interface {
	Shutdown(...ShutdownOption)
}

type ShutdownOption interface {
	apply(*shutdownOptions)
}

// ShutdownWithError shuts down with an error.
func ShutdownWithError(err error) ShutdownOption {
	return optionFunc(func(opts *shutdownOptions) {
		opts.err = err
	})
}

type optionFunc func(*shutdownOptions)

func (fn optionFunc) apply(opts *shutdownOptions) { fn(opts) }

type shutdownOptions struct {
	err error
}
