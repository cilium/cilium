// Copyright 2016-2017 Authors of Cilium
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

package proxy

import (
	"net/http"
	"net/url"
	"time"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	log "github.com/sirupsen/logrus"
)

// HTTPLogRecord wraps an accesslog.LogRecord so that we can define methods with a receiver
type HTTPLogRecord struct {
	accesslog.LogRecord
}

func newHTTPLogRecord(r Redirect, method string, url *url.URL, proto string, headers http.Header) *HTTPLogRecord {
	record := &HTTPLogRecord{
		LogRecord: accesslog.LogRecord{
			HTTP: &accesslog.LogRecordHTTP{
				Method:   method,
				URL:      url,
				Protocol: proto,
				Headers:  headers,
			},
			NodeAddressInfo: accesslog.NodeAddressInfo{
				IPv4: node.GetExternalIPv4().String(),
				IPv6: node.GetIPv6().String(),
			},
			TransportProtocol: 6, // TCP's IANA-assigned protocol number
		},
	}

	if r.IsIngress() {
		record.ObservationPoint = accesslog.Ingress
	} else {
		record.ObservationPoint = accesslog.Egress
	}

	return record
}

func (l *HTTPLogRecord) fillInfo(r Redirect, srcIPPort, dstIPPort string, srcIdentity uint32) {
	fillInfo(r, &l.LogRecord, srcIPPort, dstIPPort, srcIdentity)
}

func (l *HTTPLogRecord) log(typ accesslog.FlowType, verdict accesslog.FlowVerdict, code int, info string) {
	l.Type = typ
	l.Verdict = verdict
	l.HTTP.Code = code
	l.Info = info
	l.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	log.WithFields(log.Fields{
		accesslog.FieldType:     l.Type,
		accesslog.FieldVerdict:  l.Verdict,
		accesslog.FieldCode:     l.HTTP.Code,
		accesslog.FieldMethod:   l.HTTP.Method,
		accesslog.FieldURL:      l.HTTP.URL,
		accesslog.FieldProtocol: l.HTTP.Protocol,
		accesslog.FieldHeader:   l.HTTP.Headers,
	}).Debug("Logging HTTP L7 flow record")

	l.Log()
}
