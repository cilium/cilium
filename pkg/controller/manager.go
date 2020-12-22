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
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/google/uuid"
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
func (m *Manager) UpdateController(name string, params ControllerParams) {
	m.updateController(name, params)
}

func (m *Manager) updateController(name string, params ControllerParams) *Controller {
	start := time.Now()

	// ensure the callbacks are valid
	if params.DoFunc == nil {
		params.DoFunc = func(ctx context.Context) error {
			return undefinedDoFunc(name)
		}
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
		ctrl.updateParamsLocked(params)
		ctrl.mutex.Unlock()

		// Notify the goroutine of the params update.
		select {
		case ctrl.update <- struct{}{}:
		default:
		}

		ctrl.getLogger().Debug("Controller update time: ", time.Since(start))
	} else {
		ctrl = &Controller{
			name:       name,
			uuid:       uuid.New().String(),
			stop:       make(chan struct{}),
			update:     make(chan struct{}, 1),
			terminated: make(chan struct{}),
		}
		ctrl.updateParamsLocked(params)
		ctrl.getLogger().Debug("Starting new controller")

		if params.Context == nil {
			ctrl.ctxDoFunc, ctrl.cancelDoFunc = context.WithCancel(context.Background())
		} else {
			ctrl.ctxDoFunc, ctrl.cancelDoFunc = context.WithCancel(params.Context)
		}
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

func (m *Manager) lookup(name string) *Controller {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if c, ok := m.controllers[name]; ok {
		return c
	}

	return nil
}

func (m *Manager) removeAndReturnController(name string) (*Controller, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		return nil, fmt.Errorf("empty controller map")
	}

	oldCtrl, ok := m.controllers[name]
	if !ok {
		return nil, fmt.Errorf("unable to find controller %s", name)
	}

	m.removeController(oldCtrl)

	return oldCtrl, nil
}

// RemoveController stops and removes a controller from the manager. If DoFunc
// is currently running, DoFunc is allowed to complete in the background.
func (m *Manager) RemoveController(name string) error {
	_, err := m.removeAndReturnController(name)
	return err
}

// RemoveControllerAndWait stops and removes a controller using
// RemoveController() and then waits for it to run to completion.
func (m *Manager) RemoveControllerAndWait(name string) error {
	oldCtrl, err := m.removeAndReturnController(name)
	if err == nil {
		<-oldCtrl.terminated
	}

	return err
}

// TerminationChannel returns a channel that is closed after the controller has
// been terminated
func (m *Manager) TerminationChannel(name string) chan struct{} {
	if c := m.lookup(name); c != nil {
		return c.terminated
	}

	c := make(chan struct{})
	close(c)
	return c
}

func (m *Manager) removeAll() []*Controller {
	ctrls := []*Controller{}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		return ctrls
	}

	for _, ctrl := range m.controllers {
		m.removeController(ctrl)
		ctrls = append(ctrls, ctrl)
	}

	return ctrls
}

// RemoveAll stops and removes all controllers of the manager
func (m *Manager) RemoveAll() {
	m.removeAll()
}

// RemoveAllAndWait stops and removes all controllers of the manager and then
// waits for all controllers to exit
func (m *Manager) RemoveAllAndWait() {
	ctrls := m.removeAll()
	for _, ctrl := range ctrls {
		<-ctrl.terminated
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

// FakeManager returns a fake controller manager with the specified number of
// failing controllers. The returned manager is identical in any regard except
// for internal pointers.
func FakeManager(failingControllers int) *Manager {
	m := &Manager{
		controllers: controllerMap{},
	}

	for i := 0; i < failingControllers; i++ {
		ctrl := &Controller{
			name:              fmt.Sprintf("controller-%d", i),
			uuid:              fmt.Sprintf("%d", i),
			stop:              make(chan struct{}),
			update:            make(chan struct{}, 1),
			terminated:        make(chan struct{}),
			lastError:         fmt.Errorf("controller failed"),
			failureCount:      1,
			consecutiveErrors: 1,
		}

		ctrl.ctxDoFunc, ctrl.cancelDoFunc = context.WithCancel(context.Background())
		m.controllers[ctrl.name] = ctrl
	}

	return m
}
