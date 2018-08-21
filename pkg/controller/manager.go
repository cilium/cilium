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
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		m.controllers = controllerMap{}
	}

	if oldCtrl, ok := m.controllers[name]; ok {
		m.removeController(oldCtrl, true)
	}

	ctrl := &Controller{
		name:          name,
		params:        params,
		uuid:          uuid.NewUUID().String(),
		stop:          make(chan struct{}, 0),
		stopForUpdate: make(chan struct{}, 0),
	}

	m.controllers[ctrl.name] = ctrl

	globalStatus.mutex.Lock()
	globalStatus.controllers[ctrl.uuid] = ctrl
	globalStatus.mutex.Unlock()

	go ctrl.runController()

	ctrl.getLogger().Debug("Updated controller")

	return ctrl
}

func (m *Manager) removeController(ctrl *Controller, forUpdate bool) {
	ctrl.stopController(forUpdate)
	delete(m.controllers, ctrl.name)

	globalStatus.mutex.Lock()
	delete(globalStatus.controllers, ctrl.uuid)
	globalStatus.mutex.Unlock()

	ctrl.getLogger().Debug("Removed update controller")
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

	m.removeController(oldCtrl, false)

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
		m.removeController(ctrl, false)
	}
}

// GetStatusModel returns the status of all controllers as models.ControllerStatuses
func (m *Manager) GetStatusModel() models.ControllerStatuses {
	m.mutex.RLock()
	statuses := models.ControllerStatuses{}
	for _, c := range m.controllers {
		statuses = append(statuses, c.GetStatusModel())
	}
	m.mutex.RUnlock()

	return statuses
}
