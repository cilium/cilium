// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import (
	"fmt"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/slices"
)

// Manager stores information about loaded modules and provides a search operation.
type Manager struct {
	modulesList []string
}

func (m *Manager) Start(cell.HookContext) (err error) {
	m.modulesList, err = listModules()
	return err
}

// FindModules checks whether the given kernel modules are loaded and also
// returns a slice with names of modules which are not loaded.
func (m *Manager) FindModules(expectedNames ...string) (bool, []string) {
	return slices.SubsetOf(expectedNames, m.modulesList)
}

// FindOrLoadModules checks whether the given kernel modules are loaded and
// tries to load those which are not.
func (m *Manager) FindOrLoadModules(expectedNames ...string) error {
	found, diff := m.FindModules(expectedNames...)
	if found {
		return nil
	}
	for _, unloadedModule := range diff {
		if _, err := exec.WithTimeout(
			defaults.ExecTimeout, moduleLoader(), unloadedModule).CombinedOutput(
			nil, false); err != nil {
			return fmt.Errorf("could not load module %s: %s",
				unloadedModule, err)
		}
	}
	return nil
}

func newManager(lc cell.Lifecycle) *Manager {
	m := &Manager{}

	lc.Append(cell.Hook{OnStart: m.Start})

	return m
}
