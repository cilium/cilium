// Copyright 2018 Authors of Cilium
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

package controller

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/uuid"
)

var (
	// globalStatus is the global status of all controllers
	globalStatus = NewManager()
)

type controllerMap map[string]*Controller

// Manager is a list of controllers
type Manager struct {
	controllers controllerMap
	mutex       lock.RWMutex
}

// NewManager allocates a new manager
func NewManager() *Manager {
	return &Manager{
		controllers: controllerMap{},
	}
}

// GetGlobalStatus returns the status of all controllers
func GetGlobalStatus() models.ControllerStatuses {
	return globalStatus.GetStatusModel()
}

// UpdateController installs or updates a controller in the manager. A
// controller is identified by its name. If a controller with the name already
// exists, the controller will be shut down and replaced with the provided
// controller. Updating a controller will cause the DoFunc to be run
// immediately regardless of any previous conditions. It will also cause any
// statistics to be reset.
func (m *Manager) UpdateController(name string, params ControllerParams) *Controller {
	start := time.Now()

	// ensure the callbacks are valid
	if params.DoFunc == nil {
		params.DoFunc = func() error { return undefinedDoFunc(name) }
	}
	if params.StopFunc == nil {
		params.StopFunc = NoopFunc
	}

	m.mutex.Lock()

	if m.controllers == nil {
		m.controllers = controllerMap{}
	}

	ctrl, exists := m.controllers[name]
	if exists {
		m.mutex.Unlock()

		ctrl.getLogger().Debug("Updating existing controller")
		ctrl.mutex.Lock()
		ctrl.params = params
		ctrl.mutex.Unlock()

		// Notify the goroutine of the params update.
		select {
		case ctrl.update <- struct{}{}:
		default:
		}

		ctrl.getLogger().Debug("Controller update time: ", time.Since(start))
	} else {
		ctrl = &Controller{
			name:   name,
			params: params,
			uuid:   uuid.NewUUID().String(),
			stop:   make(chan struct{}, 0),
			update: make(chan struct{}, 1),
		}
		ctrl.getLogger().Debug("Starting new controller")

		m.controllers[ctrl.name] = ctrl
		m.mutex.Unlock()

		globalStatus.mutex.Lock()
		globalStatus.controllers[ctrl.uuid] = ctrl
		globalStatus.mutex.Unlock()

		go ctrl.runController()
	}

	return ctrl
}

func (m *Manager) removeController(ctrl *Controller) {
	ctrl.stopController()
	delete(m.controllers, ctrl.name)

	globalStatus.mutex.Lock()
	delete(globalStatus.controllers, ctrl.uuid)
	globalStatus.mutex.Unlock()

	ctrl.getLogger().Debug("Removed controller")
}

// RemoveController stops and removes a controller from the manager. If DoFunc
// is currently running, DoFunc is allowed to complete in the background.
func (m *Manager) RemoveController(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		return fmt.Errorf("empty controller map")
	}

	oldCtrl, ok := m.controllers[name]
	if !ok {
		return fmt.Errorf("unable to find controller %s", name)
	}

	m.removeController(oldCtrl)

	return nil
}

// RemoveAll stops and removes all controllers of the manager
func (m *Manager) RemoveAll() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		return
	}

	for _, ctrl := range m.controllers {
		m.removeController(ctrl)
	}
}

// GetStatusModel returns the status of all controllers as models.ControllerStatuses
func (m *Manager) GetStatusModel() models.ControllerStatuses {
	// Create a copy of pointers to current controller so we can unlock the
	// manager mutex quickly again
	controllers := controllerMap{}
	m.mutex.RLock()
	for key, c := range m.controllers {
		controllers[key] = c
	}
	m.mutex.RUnlock()

	statuses := models.ControllerStatuses{}
	for _, c := range controllers {
		statuses = append(statuses, c.GetStatusModel())
	}

	return statuses
}
