// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package options

// Option is used to configure parsers
type Option func(*Options)

// Options contains all parser options
type Options struct {
	CacheSize int
}

// CacheSize configures the amount of L7 requests cached for latency calculation
func CacheSize(size int) Option {
	return func(opt *Options) {
		opt.CacheSize = size
	}
}
