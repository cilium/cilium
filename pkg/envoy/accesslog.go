// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// ParseURL returns the URL as *net.url.URL
func ParseURL(scheme, host, path string) *url.URL {
	u, err := url.Parse(fmt.Sprintf("%s://%s/%s", scheme, host, strings.TrimPrefix(path, "/")))
	if err != nil {
		u = &url.URL{
			Scheme: scheme,
			Host:   host,
			Path:   path,
		}
	}
	return u
}

// getNetHttpHeaders returns the Headers as net.http.Header
func GetNetHttpHeaders(httpHeaders []*cilium.KeyValue) http.Header {
	headers := make(http.Header)

	for _, header := range httpHeaders {
		headers.Add(header.Key, header.Value)
	}

	return headers
}

// getProtocol returns the HTTP protocol in the format that Cilium understands
func GetProtocol(httpProtocol cilium.HttpProtocol) string {
	switch httpProtocol {
	case cilium.HttpProtocol_HTTP10:
		return "HTTP/1"
	case cilium.HttpProtocol_HTTP11:
		return "HTTP/1.1"
	case cilium.HttpProtocol_HTTP2:
		return "HTTP/2"
	default:
		return "Unknown"
	}
}

// GetFlowType returns the type of flow (request|response)
func GetFlowType(m *cilium.LogEntry) accesslog.FlowType {
	// the fall back type is request
	result := accesslog.TypeRequest

	if m != nil {
		switch m.EntryType {
		case cilium.EntryType_Denied:
			result = accesslog.TypeRequest
		case cilium.EntryType_Request:
			result = accesslog.TypeRequest
		case cilium.EntryType_Response:
			result = accesslog.TypeResponse
		}
	}

	return result
}

// GetVerdict returns the verdict performed on the flow (forwarded|denied)
func GetVerdict(m *cilium.LogEntry) accesslog.FlowVerdict {
	// the default verdict is forwarded
	result := accesslog.VerdictForwarded

	if m != nil {
		switch m.EntryType {
		case cilium.EntryType_Denied:
			result = accesslog.VerdictDenied
		}
	}

	return result
}
