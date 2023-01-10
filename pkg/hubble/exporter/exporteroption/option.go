// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporteroption

// Options stores all the configurations values for Hubble exporter.
type Options struct {
	Path       string
	MaxSizeMB  int
	MaxBackups int
	Compress   bool
}

// Option customizes the configuration of the hubble server.
type Option func(o *Options) error

// WithPath sets the Hubble export filepath. It's set to an empty string by default,
// which disables Hubble export.
func WithPath(path string) Option {
	return func(o *Options) error {
		o.Path = path
		return nil
	}
}

// WithMaxSizeMB sets the size in MB at which to rotate the Hubble export file.
func WithMaxSizeMB(size int) Option {
	return func(o *Options) error {
		o.MaxSizeMB = size
		return nil
	}
}

// WithMaxSizeMB sets the number of rotated Hubble export files to keep.
func WithMaxBackups(backups int) Option {
	return func(o *Options) error {
		o.MaxBackups = backups
		return nil
	}
}

// WithCompress specifies whether rotated files are compressed.
func WithCompress() Option {
	return func(o *Options) error {
		o.Compress = true
		return nil
	}
}
