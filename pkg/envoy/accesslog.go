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

package envoy

import (
	"net/http"

	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// GetNetHttpHeaders returns the Headers as net.http.Header
func (m *HttpLogEntry) GetNetHttpHeaders() http.Header {
	headers := make(http.Header)

	if m != nil {
		for _, header := range m.Headers {
			headers.Add(header.Key, header.Value)
		}
	}

	return headers
}

// GetProtocol returns the HTTP protocol in the format that Cilium understands
func (m *HttpLogEntry) GetProtocol() string {
	if m == nil {
		return ""
	}

	switch m.HttpProtocol {
	case Protocol_HTTP10:
		return "HTTP/1"
	case Protocol_HTTP11:
		return "HTTP/1.1"
	case Protocol_HTTP2:
		return "HTTP/2"
	default:
		return "Unknown"
	}
}

// GetFlowType returns the type of flow (request|response)
func (m *HttpLogEntry) GetFlowType() accesslog.FlowType {
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
func (m *HttpLogEntry) GetVerdict() accesslog.FlowVerdict {
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
