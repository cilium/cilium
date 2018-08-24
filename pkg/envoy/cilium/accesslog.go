// Copyright 2018 Authors of Cilium
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

package cilium

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// ParseURL returns the URL as *net.url.URL
func (pblog *HttpLogEntry) ParseURL() *url.URL {
	path := strings.TrimPrefix(pblog.Path, "/")
	u, err := url.Parse(fmt.Sprintf("%s://%s/%s", pblog.Scheme, pblog.Host, path))
	if err != nil {
		u = &url.URL{
			Scheme: pblog.Scheme,
			Host:   pblog.Host,
			Path:   pblog.Path,
		}
	}
	return u
}

// ParseURL returns the URL as *net.url.URL. Deprecated.
func (pblog *LogEntry) ParseURL() *url.URL {
	path := strings.TrimPrefix(pblog.Path, "/")
	u, err := url.Parse(fmt.Sprintf("%s://%s/%s", pblog.Scheme, pblog.Host, path))
	if err != nil {
		u = &url.URL{
			Scheme: pblog.Scheme,
			Host:   pblog.Host,
			Path:   pblog.Path,
		}
	}
	return u
}

// getNetHttpHeaders returns the Headers as net.http.Header
func getNetHttpHeaders(httpHeaders []*KeyValue) http.Header {
	headers := make(http.Header)

	for _, header := range httpHeaders {
		headers.Add(header.Key, header.Value)
	}

	return headers
}

// GetNetHttpHeaders returns the Headers as net.http.Header
func (m *HttpLogEntry) GetNetHttpHeaders() http.Header {
	if m == nil {
		return make(http.Header)
	}
	return getNetHttpHeaders(m.Headers)
}

// Deprecated
func (m *LogEntry) GetNetHttpHeaders() http.Header {
	if m == nil {
		return make(http.Header)
	}
	return getNetHttpHeaders(m.Headers)
}

// getProtocol returns the HTTP protocol in the format that Cilium understands
func getProtocol(httpProtocol HttpProtocol) string {
	switch httpProtocol {
	case HttpProtocol_HTTP10:
		return "HTTP/1"
	case HttpProtocol_HTTP11:
		return "HTTP/1.1"
	case HttpProtocol_HTTP2:
		return "HTTP/2"
	default:
		return "Unknown"
	}
}

// GetProtocol returns the HTTP protocol in the format that Cilium understands
func (m *HttpLogEntry) GetProtocol() string {
	if m == nil {
		return ""
	}
	return getProtocol(m.HttpProtocol)
}

// Deprecated
func (m *LogEntry) GetProtocol() string {
	if m == nil {
		return ""
	}
	return getProtocol(m.HttpProtocol)
}

// GetFlowType returns the type of flow (request|response)
func (m *LogEntry) GetFlowType() accesslog.FlowType {
	// the fall back type is request
	result := accesslog.TypeRequest

	if m != nil {
		switch m.EntryType {
		case EntryType_Denied:
			result = accesslog.TypeRequest
		case EntryType_Request:
			result = accesslog.TypeRequest
		case EntryType_Response:
			result = accesslog.TypeResponse
		}
	}

	return result
}

// GetVerdict returns the verdict performed on the flow (forwarded|denied)
func (m *LogEntry) GetVerdict() accesslog.FlowVerdict {
	// the default verdict is forwarded
	result := accesslog.VerdictForwarded

	if m != nil {
		switch m.EntryType {
		case EntryType_Denied:
			result = accesslog.VerdictDenied
		}
	}

	return result
}
