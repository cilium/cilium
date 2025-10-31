// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loading

import (
	"io/fs"
	"net/http"
	"os"
	"time"
)

type (
	// Option provides options for loading a file over HTTP or from a file.
	Option func(*options)

	httpOptions struct {
		httpTimeout       time.Duration
		basicAuthUsername string
		basicAuthPassword string
		customHeaders     map[string]string
		client            *http.Client
	}

	fileOptions struct {
		fs fs.ReadFileFS
	}

	options struct {
		httpOptions
		fileOptions
	}
)

func (fo fileOptions) ReadFileFunc() func(string) ([]byte, error) {
	if fo.fs == nil {
		return os.ReadFile
	}

	return fo.fs.ReadFile
}

// WithTimeout sets a timeout for the remote file loader.
//
// The default timeout is 30s.
func WithTimeout(timeout time.Duration) Option {
	return func(o *options) {
		o.httpTimeout = timeout
	}
}

// WithBasicAuth sets a basic authentication scheme for the remote file loader.
func WithBasicAuth(username, password string) Option {
	return func(o *options) {
		o.basicAuthUsername = username
		o.basicAuthPassword = password
	}
}

// WithCustomHeaders sets custom headers for the remote file loader.
func WithCustomHeaders(headers map[string]string) Option {
	return func(o *options) {
		if o.customHeaders == nil {
			o.customHeaders = make(map[string]string, len(headers))
		}

		for header, value := range headers {
			o.customHeaders[header] = value
		}
	}
}

// WithHTTClient overrides the default HTTP client used to fetch a remote file.
//
// By default, [http.DefaultClient] is used.
func WithHTTPClient(client *http.Client) Option {
	return func(o *options) {
		o.client = client
	}
}

// WithFileFS sets a file system for the local file loader.
//
// If the provided file system is a [fs.ReadFileFS], the ReadFile function is used.
// Otherwise, ReadFile is wrapped using [fs.ReadFile].
//
// By default, the file system is the one provided by the os package.
//
// For example, this may be set to consume from an embedded file system, or a rooted FS.
func WithFS(filesystem fs.FS) Option {
	return func(o *options) {
		if rfs, ok := filesystem.(fs.ReadFileFS); ok {
			o.fs = rfs

			return
		}
		o.fs = readFileFS{FS: filesystem}
	}
}

type readFileFS struct {
	fs.FS
}

func (r readFileFS) ReadFile(name string) ([]byte, error) {
	return fs.ReadFile(r.FS, name)
}

func optionsWithDefaults(opts []Option) options {
	const defaultTimeout = 30 * time.Second

	o := options{
		// package level defaults
		httpOptions: httpOptions{
			httpTimeout: defaultTimeout,
			client:      http.DefaultClient,
		},
	}

	for _, apply := range opts {
		apply(&o)
	}

	return o
}
