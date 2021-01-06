// Copyright 2017-2019 Authors of Cilium
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

package metrics

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/prometheus/client_golang/prometheus"
)

// APIEventTSHelper is intended to be a global middleware to track metrics
// around API calls.
// It records the timestamp of an API call in the provided gauge.
type APIEventTSHelper struct {
	Next      http.Handler
	TSGauge   prometheus.Gauge
	Histogram prometheus.ObserverVec
}

type responderWrapper struct {
	http.ResponseWriter
	code int
}

func (rw *responderWrapper) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

// getShortPath returns the API path trimmed after the 3rd slash.
// examples:
//  "/v1/config" -> "/v1/config"
//  "/v1/endpoint/cilium-local:0" -> "/v1/endpoint"
//  "/v1/endpoint/container-id:597.." -> "/v1/endpoint"
func getShortPath(s string) string {
	var idxSum int
	for nThSlash := 0; nThSlash < 3; nThSlash++ {
		idx := strings.IndexByte(s[idxSum:], '/')
		if idx == -1 {
			return s
		}
		idxSum += idx + 1
	}
	return s[:idxSum-1]
}

// ServeHTTP implements the http.Handler interface. It records the timestamp
// this API call began at, then chains to the next handler.
func (m *APIEventTSHelper) ServeHTTP(r http.ResponseWriter, req *http.Request) {
	m.TSGauge.SetToCurrentTime()
	duration := spanstat.Start()
	rw := &responderWrapper{ResponseWriter: r}
	m.Next.ServeHTTP(rw, req)
	if req != nil && req.URL != nil && req.URL.Path != "" {
		path := getShortPath(req.URL.Path)
		took := float64(duration.End(true).Total().Seconds())
		m.Histogram.WithLabelValues(path, req.Method, strconv.Itoa(rw.code)).Observe(took)
	}
}
