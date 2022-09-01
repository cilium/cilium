// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/multierr"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

// PluginConflicts is an optional interface that plugins can implement to
// declare other plugins they conflict with.
type PluginConflicts interface {
	// ConflictingPlugin returns a list of other plugin names that this plugin
	// conflicts with.
	ConflictingPlugins() []string
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
	ProcessFlow(ctx context.Context, flow *pb.Flow) error

	// Status returns the configuration status of the metric handler
	Status() string
}

// ProcessFlow processes a flow by calling ProcessFlow it on to all enabled
// metric handlers
func (h Handlers) ProcessFlow(ctx context.Context, flow *pb.Flow) error {
	var processingErr error
	for _, mh := range h {
		err := mh.ProcessFlow(ctx, flow)
		// Continue running the remaining metrics handlers, since one failing
		// shouldn't impact the other metrics handlers.
		processingErr = multierr.Append(processingErr, err)
	}
	return processingErr
}

var registry = NewRegistry(
	logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble"),
)

// DefaultRegistry returns the default registry of all available metric plugins
func DefaultRegistry() *Registry {
	return registry
}
