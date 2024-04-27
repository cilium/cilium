// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
)

// Registry holds a set of registered metric handlers
type Registry struct {
	log      logrus.FieldLogger
	mutex    lock.Mutex
	handlers map[string]Plugin
}

// NewRegistry returns a new Registry
func NewRegistry(log logrus.FieldLogger) *Registry {
	return &Registry{
		log: log,
	}
}

// Register registers a metrics handler plugin with the manager. After
// registration, the metrics handler plugin can be enabled via
// HandlerManager.ConfigureHandlers().
func (r *Registry) Register(name string, p Plugin) {
	r.mutex.Lock()
	if r.handlers == nil {
		r.handlers = map[string]Plugin{}
	}
	r.handlers[name] = p
	r.mutex.Unlock()
}

type NamedHandler struct {
	Name         string
	Handler      Handler
	MetricConfig *MetricConfig
}

// ConfigureHandlers enables a set of metric handlers and initializes them.
// Only metrics handlers which have been previously registered via the
// Register() function can be configured.
func (r *Registry) ConfigureHandlers(registry *prometheus.Registry, enabled *Config) (*Handlers, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var enabledHandlers []NamedHandler
	metricNames := enabled.GetMetricNames()
	for _, metricsConfig := range enabled.Metrics {
		plugin, ok := r.handlers[metricsConfig.Name]
		if !ok {
			return nil, fmt.Errorf("metric '%s' does not exist", metricsConfig.Name)
		}

		if cp, ok := plugin.(PluginConflicts); ok {
			for _, conflict := range cp.ConflictingPlugins() {
				if _, conflictExists := metricNames[conflict]; conflictExists {
					return nil, fmt.Errorf("plugin %s conflicts with plugin %s", metricsConfig.Name, conflict)
				}
			}
		}

		h := NamedHandler{
			Name:         metricsConfig.Name,
			Handler:      plugin.NewHandler(),
			MetricConfig: metricsConfig,
		}
		enabledHandlers = append(enabledHandlers, h)
	}

	return NewHandlers(r.log, registry, enabledHandlers)
}
