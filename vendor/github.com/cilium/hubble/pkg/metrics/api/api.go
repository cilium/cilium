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

package api

import (
	"strings"

	"github.com/cilium/hubble/pkg/api/v1"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultPrometheusNamespace is the default namespace (prefix) used
	// for all Hubble related Prometheus metrics
	DefaultPrometheusNamespace = "hubble"
)

// Map is a set of metrics with their corresponding options
type Map map[string]Options

// ParseMetricList parses a slice of metric options and returns a map of
// enabled metrics
func ParseMetricList(enabledMetrics []string) (m Map) {
	m = Map{}
	for _, metric := range enabledMetrics {
		s := strings.SplitN(metric, ":", 2)
		if len(s) == 2 {
			m[s[0]] = ParseOptions(s[1])
		} else {
			m[s[0]] = Options{}
		}
	}
	return
}

// Handlers is a slice of metric handler
type Handlers []Handler

// Plugin is a metric plugin. A metric plugin is associated a name and is
// responsible to spawn metric handlers of a certain type.
type Plugin interface {
	// NewHandler returns a new metric handler of the respective plugin
	NewHandler() Handler

	// HelpText returns a human readable help text including a description
	// of the options
	HelpText() string
}

// Handler is a metric handler. It is called upon receival of raw event data
// and is responsible to perform metrics accounting according to the scope of
// the metrics plugin.
type Handler interface {
	// Init must initialize the metric handler by validating and parsing
	// the options and then registering all required metrics with the
	// specifies Prometheus registry
	Init(registry *prometheus.Registry, options Options) error

	// ProcessFlow must processes a flow event and perform metrics
	// accounting
	ProcessFlow(flow v1.Flow)

	// Status returns the configuration status of the metric handler
	Status() string
}

// ProcessFlow processes a flow by calling ProcessFlow it on to all enabled
// metric handlers
func (h Handlers) ProcessFlow(flow v1.Flow) {
	for _, mh := range h {
		mh.ProcessFlow(flow)
	}
}

var registry = NewRegistry()

// DefaultRegistry returns the default registry of all available metric plugins
func DefaultRegistry() *Registry {
	return registry
}
