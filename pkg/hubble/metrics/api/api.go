// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// DefaultPrometheusNamespace is the default namespace (prefix) used
	// for all Hubble related Prometheus metrics
	DefaultPrometheusNamespace = "hubble"
)

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
	Init(registry *prometheus.Registry, options *MetricConfig) error

	// ListMetricVec returns an array of MetricVec used by a handler
	ListMetricVec() []*prometheus.MetricVec

	// Context used by this metrics handler
	Context() *ContextOptions

	// Status returns the configuration status of the metric handler
	Status() string

	// HandleConfigurationUpdate updates the metric handler configuration
	HandleConfigurationUpdate(cfg *MetricConfig) error

	// Deinit deregisters the metrics from the Prometheus registry
	// and cleans up internal handler state
	Deinit(registry *prometheus.Registry) error

	// ProcessFlow must processes a flow event and perform metrics
	// accounting
	ProcessFlow(ctx context.Context, flow *pb.Flow) error
}

func InitHandlers(log *slog.Logger, registry *prometheus.Registry, in *[]NamedHandler) (*[]NamedHandler, error) {
	var handlers []NamedHandler
	for _, item := range *in {
		if err := InitHandler(log, registry, &item); err != nil {
			return nil, err
		}
		handlers = append(handlers, item)
	}
	return &handlers, nil
}

func InitHandler(log *slog.Logger, registry *prometheus.Registry, item *NamedHandler) error {
	if err := item.Handler.Init(registry, item.MetricConfig); err != nil {
		return fmt.Errorf("unable to initialize metric '%s': %w", item.Name, err)
	}

	log.Info(
		"Configured metrics plugin",
		logfields.Name, item.Name,
		logfields.Status, item.Handler.Status(),
	)

	return nil
}

// ProcessCiliumEndpointDeletion queries all handlers for a list of MetricVec and removes
// metrics directly associated to pod of the deleted cilium endpoint.
func ProcessCiliumEndpointDeletion(endpoint *types.CiliumEndpoint, handlers []NamedHandler) {
	for _, h := range handlers {
		for _, mv := range h.Handler.ListMetricVec() {
			if ctx := h.Handler.Context(); ctx != nil {
				ctx.DeleteMetricsAssociatedWithPod(endpoint.GetName(), endpoint.GetNamespace(), mv)
			}
		}
	}
}

var registry = NewRegistry()

// DefaultRegistry returns the default registry of all available metric plugins
func DefaultRegistry() *Registry {
	return registry
}

type ContextValues []string

// ContextOptions is a structure used for configuring Hubble metrics context options
type ContextOptionConfig struct {
	Name   string        `json:"name,omitempty" yaml:"name,omitempty"`
	Values ContextValues `json:"values,omitempty" yaml:"values,omitempty"`
}

// MetricConfig represents a Hubble metric, its options and which resources it applies to.
// It can hold data parsed from the "hubble-dynamic-metrics-config" K8S ConfigMap.
type MetricConfig struct {
	// Name of the metric
	Name                 string                 `json:"name,omitempty" yaml:"name,omitempty"`
	ContextOptionConfigs []*ContextOptionConfig `json:"contextOptions,omitempty" yaml:"contextOptions,omitempty"`
	// IncludeFilters controls which resources the metric applies to
	IncludeFilters []*pb.FlowFilter `json:"includeFilters,omitempty" yaml:"includeFilters,omitempty"`
	// IncludeFilters controls which resources the metric doesn't apply to
	ExcludeFilters []*pb.FlowFilter `json:"excludeFilters,omitempty" yaml:"excludeFilters,omitempty"`
}

// Config represents the structure used for configuring
// Hubble metrics context options
type Config struct {
	Metrics []*MetricConfig `json:"metrics,omitempty" yaml:"metrics,omitempty"`
}

func (d *Config) GetMetricNames() map[string]*MetricConfig {
	metrics := make(map[string]*MetricConfig)
	for _, m := range d.Metrics {
		metrics[m.Name] = m
	}
	return metrics
}

func ParseStaticMetricsConfig(enabledMetrics []string) (metricConfigs *Config) {
	//exhaustruct:ignore
	metricConfigs = &Config{}
	for _, metric := range enabledMetrics {
		s := strings.SplitN(metric, ":", 2)
		config := &MetricConfig{
			Name:                 s[0],
			IncludeFilters:       []*pb.FlowFilter{},
			ExcludeFilters:       []*pb.FlowFilter{},
			ContextOptionConfigs: []*ContextOptionConfig{},
		}
		if len(s) == 2 {
			config.ContextOptionConfigs = parseOptionConfigs(s[1])
		}
		metricConfigs.Metrics = append(metricConfigs.Metrics, config)
	}

	return
}

func parseOptionConfigs(s string) (options []*ContextOptionConfig) {
	options = []*ContextOptionConfig{}

	for option := range strings.SplitSeq(s, ";") {
		if option == "" {
			continue
		}

		kv := strings.SplitN(option, "=", 2)
		ctxOption := &ContextOptionConfig{
			Name: kv[0],
		}
		if len(kv) == 2 {
			ctxOption.Values = parseOptionValues(kv[1])
		} else {
			ctxOption.Values = []string{""}
		}
		options = append(options, ctxOption)
	}

	return
}

func parseOptionValues(s string) (values ContextValues) {
	values = ContextValues{}

	if strings.Contains(s, "|") {
		for option := range strings.SplitSeq(s, "|") {
			if option == "" {
				continue
			}
			values = append(values, option)
		}
	} else {
		// temporarily handling comma separated values for labels context
		for option := range strings.SplitSeq(s, ",") {
			if option == "" {
				continue
			}
			values = append(values, option)
		}
	}
	return
}
