// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/spanstat"
)

// APIEventTSHelper is intended to be a global middleware to track metrics
// around API calls.
// It records the timestamp of an API call in the provided gauge.
type APIEventTSHelper struct {
	Next      http.Handler
	TSGauge   GaugeVec
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
	reqOk := req != nil && req.URL != nil && req.URL.Path != ""
	var path string
	if reqOk {
		path = getShortPath(req.URL.Path)
		m.TSGauge.WithLabelValues(LabelEventSourceAPI, path, req.Method).SetToCurrentTime()
	}
	duration := spanstat.Start()
	rw := &responderWrapper{ResponseWriter: r}
	m.Next.ServeHTTP(rw, req)
	if reqOk {
		took := float64(duration.End(true).Total().Seconds())
		m.Histogram.WithLabelValues(path, req.Method, strconv.Itoa(rw.code)).Observe(took)
	}
}
