// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
