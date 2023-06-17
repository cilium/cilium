// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import (
	"fmt"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/slices"
)

// ModulesManager is a manager which stores information about loaded modules
// and provides a search operation.
type ModulesManager struct {
	modulesList []string
}

// Init initializes the internal modules information store of modules manager.
func (m *ModulesManager) Init() error {
	modulesList, err := listModules()
	if err != nil {
		return err
	}
	m.modulesList = modulesList
	return nil
}

// FindModules checks whether the given kernel modules are loaded and also
// returns a slice with names of modules which are not loaded.
func (m *ModulesManager) FindModules(expectedNames ...string) (bool, []string) {
	return slices.SubsetOf(expectedNames, m.modulesList)
}

// FindOrLoadModules checks whether the given kernel modules are loaded and
// tries to load those which are not.
func (m *ModulesManager) FindOrLoadModules(expectedNames ...string) error {
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
