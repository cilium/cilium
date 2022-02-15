// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorderoption

import (
	"github.com/cilium/cilium/pkg/defaults"
)

// Options stores all the configuration values for the Hubble recorder.
type Options struct {
	// StoragePath is the path to the directory where the captured pcap files
	// will be stored
	StoragePath string
}

// Default contains the default values
var Default = Options{
	StoragePath: defaults.HubbleRecorderStoragePath,
}

// Option customizes the Hubble recorder's configuration.
type Option func(o *Options) error

// WithStoragePath controls the path to the directory where the captured pcap
// files will be stored
func WithStoragePath(path string) Option {
	return func(o *Options) error {
		o.StoragePath = path
		return nil
	}
}
