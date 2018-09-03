// Copyright 2017 Authors of Cilium
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

	"github.com/prometheus/client_golang/prometheus"
)

// APIEventTSHelper is intended to be a global middleware to track metrics
// around API calls.
// It records the timestamp of an API call in the provided gauge.
type APIEventTSHelper struct {
	Next    http.Handler
	TSGauge prometheus.Gauge
}

// ServeHTTP implements the http.Handler interface. It records the timestamp
// this API call began at, then chains to the next handler.
func (m *APIEventTSHelper) ServeHTTP(r http.ResponseWriter, req *http.Request) {
	m.TSGauge.SetToCurrentTime()
	m.Next.ServeHTTP(r, req)
}
