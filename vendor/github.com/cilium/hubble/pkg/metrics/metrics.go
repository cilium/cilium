// Copyright 2019 Authors of Hubble
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

	"github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/metrics/api"
	_ "github.com/cilium/hubble/pkg/metrics/dns"               // invoke init
	_ "github.com/cilium/hubble/pkg/metrics/drop"              // invoke init
	_ "github.com/cilium/hubble/pkg/metrics/flow"              // invoke init
	_ "github.com/cilium/hubble/pkg/metrics/http"              // invoke init
	_ "github.com/cilium/hubble/pkg/metrics/icmp"              // invoke init
	_ "github.com/cilium/hubble/pkg/metrics/port-distribution" // invoke init
	_ "github.com/cilium/hubble/pkg/metrics/tcp"               // invoke init

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	enabledMetrics api.Handlers
	registry       = prometheus.NewPedanticRegistry()
)

// ProcessFlow processes a flow and updates metrics
func ProcessFlow(flow v1.Flow) {
	if enabledMetrics != nil {
		enabledMetrics.ProcessFlow(flow)
	}
}

// Init initialies the metrics system
func Init(address string, enabled api.Map) (<-chan error, error) {
	e, err := api.DefaultRegistry().ConfigureHandlers(registry, enabled)
	if err != nil {
		return nil, err
	}
	enabledMetrics = e

	errChan := make(chan error, 1)

	go func() {
		http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		errChan <- http.ListenAndServe(address, nil)
	}()

	return errChan, nil
}
