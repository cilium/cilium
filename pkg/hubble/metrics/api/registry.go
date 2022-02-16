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

// ConfigureHandlers enables a set of metric handlers and initializes them.
// Only metrics handlers which have been previously registered via the
// Register() function can be configured.
func (r *Registry) ConfigureHandlers(registry *prometheus.Registry, enabled Map) (Handlers, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	initialized := make(Handlers, 0, len(enabled))
	for name, opts := range enabled {
		plugin, ok := r.handlers[name]
		if !ok {
			return nil, fmt.Errorf("metric '%s' does not exist", name)
		}

		handler := plugin.NewHandler()
		if err := handler.Init(registry, opts); err != nil {
			return nil, fmt.Errorf("unable to initialize metric '%s': %s", name, err)
		}
		r.log.WithFields(logrus.Fields{"name": name, "status": handler.Status()}).Info("Configured metrics plugin")

		initialized = append(initialized, handler)
	}

	return initialized, nil
}
