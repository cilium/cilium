// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package http

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type httpPlugin struct{}

func (p *httpPlugin) NewHandler() api.Handler {
	return &httpHandler{}
}

func (p *httpPlugin) HelpText() string {
	return `http - HTTP metrics
Metrics related to the HTTP protocol

Metrics:
  http_requests_total           - Count of HTTP requests by methods.
  http_responses_total          - Count of HTTP responses by methods and status codes.
  http_request_duration_seconds - Median, 90th and 99th percentile of request duration.

Options:` +
		api.ContextOptionsHelp
}

func (p *httpPlugin) ConflictingPlugins() []string {
	return []string{"httpV2"}
}

type httpV2Plugin struct{}

func (p *httpV2Plugin) NewHandler() api.Handler {
	return &httpHandler{useV2: true}
}

func (p *httpV2Plugin) HelpText() string {
	return `httpV2 - HTTP metrics
Metrics related to the HTTP protocol

Metrics:
  http_requests_total           - Count of HTTP requests by method, protocol, and status code.
  http_request_duration_seconds - Median, 90th and 99th percentile of request duration.

Options:` +
		api.ContextOptionsHelp
}

func (p *httpV2Plugin) ConflictingPlugins() []string {
	return []string{"http"}
}

func init() {
	api.DefaultRegistry().Register("http", &httpPlugin{})
	api.DefaultRegistry().Register("httpV2", &httpV2Plugin{})
}
