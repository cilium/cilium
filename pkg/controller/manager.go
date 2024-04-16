// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"fmt"

	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// globalStatus is the global status of all controllers
	globalStatus = NewManager()
)

type controllerMap map[string]*managedController

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

// UpdateController installs or updates a controller in the
// manager. A controller is primarily identified by its name.
// If a controller with the name already exists, the controller
// will be shut down and replaced with the provided controller.
//
// Updating a controller will cause the DoFunc to be run immediately regardless
// of any previous conditions. It will also cause any statistics to be reset.
func (m *Manager) UpdateController(name string, params ControllerParams) {
	m.updateController(name, params)
}

func (m *Manager) updateController(name string, params ControllerParams) *managedController {
	start := time.Now()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		m.controllers = controllerMap{}
	}

	if params.Group.Name == "" {
		log.Errorf(
			"Controller initialized with unpopulated group information. " +
				"Metrics will not be exported for this controller.")
	}

	ctrl := m.lookupLocked(name)
	if ctrl != nil {
		ctrl.getLogger().Debug("Updating existing controller")
		ctrl.updateParamsLocked(params)

		// Notify the goroutine of the params update.
		select {
		case ctrl.update <- ctrl.params:
		default:
		}

		ctrl.getLogger().Debug("Controller update time: ", time.Since(start))
	} else {
		return m.createControllerLocked(name, params)
	}

	return ctrl
}

func (m *Manager) createControllerLocked(name string, params ControllerParams) *managedController {
	ctrl := &managedController{
		controller: controller{
			name:       name,
			group:      params.Group,
			uuid:       uuid.New().String(),
			stop:       make(chan struct{}),
			update:     make(chan ControllerParams, 1),
			trigger:    make(chan struct{}, 1),
			terminated: make(chan struct{}),
		},
	}
	ctrl.updateParamsLocked(params)
	ctrl.getLogger().Debug("Starting new controller")

	m.controllers[ctrl.name] = ctrl

	globalStatus.mutex.Lock()
	globalStatus.controllers[ctrl.uuid] = ctrl
	globalStatus.mutex.Unlock()

	go ctrl.runController(ctrl.params)
	return ctrl
}

// CreateController installs a new controller in the
// manager.  If a controller with the name already exists
// this method returns false without triggering, otherwise
// creates the controller and runs it immediately.
func (m *Manager) CreateController(name string, params ControllerParams) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers != nil {
		if ctrl := m.lookupLocked(name); ctrl != nil {
			return false
		}
	} else {
		m.controllers = controllerMap{}
	}
	m.createControllerLocked(name, params)
	return true
}

func (m *Manager) removeController(ctrl *managedController) {
	ctrl.stopController()
	delete(m.controllers, ctrl.name)

	globalStatus.mutex.Lock()
	delete(globalStatus.controllers, ctrl.uuid)
	globalStatus.mutex.Unlock()

	ctrl.getLogger().Debug("Removed controller")
}

func (m *Manager) lookup(name string) *managedController {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.lookupLocked(name)
}

func (m *Manager) lookupLocked(name string) *managedController {
	if c, ok := m.controllers[name]; ok {
		return c
	}
	return nil
}

func (m *Manager) removeAndReturnController(name string) (*managedController, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.controllers == nil {
		return nil, fmt.Errorf("empty controller map")
	}

	oldCtrl := m.lookupLocked(name)
	if oldCtrl == nil {
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

func (m *Manager) removeAll() []*managedController {
	ctrls := []*managedController{}

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

// TriggerController triggers the controller with the specified name.
func (m *Manager) TriggerController(name string) {
	ctrl := m.lookup(name)
	if ctrl == nil {
		return
	}

	select {
	case ctrl.trigger <- struct{}{}:
	default:
	}
}

type managedController struct {
	controller

	params       ControllerParams
	cancelDoFunc context.CancelFunc
}

// updateParamsLocked sanitizes and sets the controller's parameters.
//
// If the RunInterval exceeds ControllerMaxInterval, it will be capped.
//
// Manager's mutex must be held
func (c *managedController) updateParamsLocked(params ControllerParams) {
	// ensure the callbacks are valid
	if params.DoFunc == nil {
		params.DoFunc = func(ctx context.Context) error {
			return undefinedDoFunc(c.name)
		}
	}
	if params.StopFunc == nil {
		params.StopFunc = NoopFunc
	}

	// Enforce max controller interval
	maxInterval := time.Duration(option.Config.MaxControllerInterval) * time.Second
	if maxInterval > 0 && params.RunInterval > maxInterval {
		c.getLogger().Infof("Limiting interval to %s", maxInterval)
		params.RunInterval = maxInterval
	}

	// Save current context on update if not canceling
	ctx := c.params.Context
	// Check if the current context needs to be cancelled
	if c.params.CancelDoFuncOnUpdate && c.cancelDoFunc != nil {
		c.cancelDoFunc()
		c.params.Context = nil
	}

	// (re)set the context as the previous might have been cancelled
	if c.params.Context == nil {
		if params.Context == nil {
			ctx, c.cancelDoFunc = context.WithCancel(context.Background())
		} else {
			ctx, c.cancelDoFunc = context.WithCancel(params.Context)
		}
	}

	c.params = params
	c.params.Context = ctx
}

func (c *managedController) stopController() {
	if c.cancelDoFunc != nil {
		c.cancelDoFunc()
	}

	close(c.stop)
}

// GetStatusModel returns a models.ControllerStatus representing the
// controller's configuration & status
func (c *managedController) GetStatusModel() *models.ControllerStatus {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	status := &models.ControllerStatus{
		Name: c.name,
		UUID: strfmt.UUID(c.uuid),
		Configuration: &models.ControllerStatusConfiguration{
			ErrorRetry:     !c.params.NoErrorRetry,
			ErrorRetryBase: strfmt.Duration(c.params.ErrorRetryBaseDuration),
			Interval:       strfmt.Duration(c.params.RunInterval),
		},
		Status: &models.ControllerStatusStatus{
			SuccessCount:            int64(c.successCount),
			LastSuccessTimestamp:    strfmt.DateTime(c.lastSuccessStamp),
			FailureCount:            int64(c.failureCount),
			LastFailureTimestamp:    strfmt.DateTime(c.lastErrorStamp),
			ConsecutiveFailureCount: int64(c.consecutiveErrors),
		},
	}

	if c.lastError != nil {
		status.Status.LastFailureMsg = c.lastError.Error()
	}

	return status
}
