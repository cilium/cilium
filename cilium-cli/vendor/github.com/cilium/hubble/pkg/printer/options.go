// Copyright 2019-2021 Authors of Hubble
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

package printer

import (
	"io"
)

// Output enum of the printer.
type Output int

const (
	// TabOutput prints flows in even tab-aligned columns.
	TabOutput Output = iota
	// JSONOutput prints flows as json.
	JSONOutput
	// CompactOutput prints flows as compact as possible (similar to monitor).
	CompactOutput
	// DictOutput presents the same information as TabOutput, but each flow is
	// presented as a key:value dictionary, similar to \G output of mysql.
	DictOutput
	// JSONPBOutput prints GetFlowsResponse as JSON according to proto3's JSON mapping.
	JSONPBOutput
)

// Options for the printer.
type Options struct {
	output              Output
	w                   io.Writer
	werr                io.Writer
	enableDebug         bool
	enableIPTranslation bool
	nodeName            bool
	timeFormat          string
	color               string
}

// Option ...
type Option func(*Options)

// JSON encoded output from the printer.
func JSON() Option {
	return func(opts *Options) {
		opts.output = JSONOutput
	}
}

// JSONPB encodes GetFlowsResponse as JSON according to proto3's JSON mapping.
func JSONPB() Option {
	return func(opts *Options) {
		opts.output = JSONPBOutput
	}
}

// Compact ...
func Compact() Option {
	return func(opts *Options) {
		opts.output = CompactOutput
	}
}

// Dict ...
func Dict() Option {
	return func(opts *Options) {
		opts.output = DictOutput
	}
}

// Tab prints flows in even tab-aligned columns.
func Tab() Option {
	return func(opts *Options) {
		opts.output = TabOutput
	}
}

// Writer sets the custom destination for where the bytes are sent.
func Writer(w io.Writer) Option {
	return func(opts *Options) {
		opts.w = w
	}
}

// IgnoreStderr configures the output to not print any
func IgnoreStderr() Option {
	return func(opts *Options) {
		opts.werr = io.Discard
	}
}

// WithColor set the color mode. The when argument is one of:
// - "auto": color mode is enabled when the standard output is connected to a
//   terminal.
// - "always": color mode is enabled no matter to standard output.
// - "never": color mode is always disabled.
// Any other value of when means "auto", which is the default.
// The color mode is only applied with in Dict or Compact mode. For any other
// mode, color is always disabled.
func WithColor(when string) Option {
	return func(opts *Options) {
		opts.color = when
	}
}

// WithDebug enables debug messages
func WithDebug() Option {
	return func(opts *Options) {
		opts.enableDebug = true
	}
}

// WithIPTranslation enables translation from IPs to pod names, FQDNs, and service names.
func WithIPTranslation() Option {
	return func(opts *Options) {
		opts.enableIPTranslation = true
	}
}

// WithNodeName enables printing the node name.
func WithNodeName() Option {
	return func(opts *Options) {
		opts.nodeName = true
	}
}

// WithTimeFormat specifies the time format layout to use when printing out
// timestamps. This option has no effect if JSON or JSONPB option is used.
// The layout must be a time format layout as specified in the standard
// library's time package.
func WithTimeFormat(layout string) Option {
	return func(opts *Options) {
		opts.timeFormat = layout
	}
}
