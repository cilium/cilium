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
	"fmt"
	"sync"

	"github.com/cilium/hubble/pkg/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Registry holds a set of registered metric handlers
type Registry struct {
	mutex    sync.Mutex
	handlers map[string]Plugin
}

// NewRegistry returns a new Registry
func NewRegistry() *Registry {
	return &Registry{}
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
	var (
		initialized Handlers
		log         = logger.GetLogger()
	)

	r.mutex.Lock()
	defer r.mutex.Unlock()

	for name, opts := range enabled {
		plugin, ok := r.handlers[name]
		if !ok {
			return nil, fmt.Errorf("metric '%s' does not exist", name)
		}

		handler := plugin.NewHandler()
		if err := handler.Init(registry, opts); err != nil {
			return nil, fmt.Errorf("unable to initialize metric '%s': %s", name, err)
		}
		log.WithFields(logrus.Fields{"name": name, "status": handler.Status()}).Info("Configured metrics plugin")

		initialized = append(initialized, handler)
	}

	return initialized, nil
}
