// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	pb "github.com/cilium/cilium/api/v1/flow"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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

// Handlers contains all the metrics handlers.
type Handlers struct {
	handlers       []Handler
	flowProcessors []FlowProcessor
}

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

// Handler is a basic metric handler.
type Handler interface {
	// Init must initialize the metric handler by validating and parsing
	// the options and then registering all required metrics with the
	// specifies Prometheus registry
	Init(registry *prometheus.Registry, options Options) error

	// ListMetricVec returns an array of MetricVec used by a handler
	ListMetricVec() []*prometheus.MetricVec

	// Context used by this metrics handler
	Context() *ContextOptions

	// Status returns the configuration status of the metric handler
	Status() string
}

// FlowProcessor is a metric handler which requires flows to perform metrics
// accounting.
// It is called upon receival of raw event data and is responsible
// to perform metrics accounting according to the scope of the metrics plugin.
type FlowProcessor interface {
	// ProcessFlow must processes a flow event and perform metrics
	// accounting
	ProcessFlow(ctx context.Context, flow *pb.Flow) error
}

func NewHandlers(log logrus.FieldLogger, registry *prometheus.Registry, in []NamedHandler) (*Handlers, error) {
	var handlers Handlers
	for _, item := range in {
		handlers.handlers = append(handlers.handlers, item.Handler)
		if fp, ok := item.Handler.(FlowProcessor); ok {
			handlers.flowProcessors = append(handlers.flowProcessors, fp)
		}

		if err := item.Handler.Init(registry, item.Options); err != nil {
			return nil, fmt.Errorf("unable to initialize metric '%s': %s", item.Name, err)
		}

		log.WithFields(logrus.Fields{
			"name":   item.Name,
			"status": item.Handler.Status(),
		}).Info("Configured metrics plugin")
	}
	return &handlers, nil
}

// ProcessFlow processes a flow by calling ProcessFlow it on to all enabled
// metric handlers
func (h Handlers) ProcessFlow(ctx context.Context, flow *pb.Flow) error {
	var processingErr error
	for _, fp := range h.flowProcessors {
		err := fp.ProcessFlow(ctx, flow)
		// Continue running the remaining metrics handlers, since one failing
		// shouldn't impact the other metrics handlers.
		processingErr = multierr.Append(processingErr, err)
	}
	return processingErr
}

// ProcessPodDeletion queries all handlers for a list of MetricVec and removes
// metrics directly associated to deleted pod.
func (h Handlers) ProcessPodDeletion(pod *slim_corev1.Pod) {
	for _, h := range h.handlers {
		for _, mv := range h.ListMetricVec() {
			if ctx := h.Context(); ctx != nil {
				ctx.DeleteMetricsAssociatedWithPod(pod.GetName(), pod.GetNamespace(), mv)
			}
		}
	}
}

var registry = NewRegistry(
	logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble"),
)

// DefaultRegistry returns the default registry of all available metric plugins
func DefaultRegistry() *Registry {
	return registry
}
