// Copyright 2019 Authors of Cilium
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

package modules

import (
	"github.com/cilium/cilium/pkg/set"
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

// FindOrLoadModules checks whether the given kernel modules are loaded and
// tries to load those which are not.
func (m *ModulesManager) FindOrLoadModules(expectedModules map[string]string) error {
	found, diff := set.MapSubsetOfSlice(expectedModules, m.modulesList)
	if found {
		return nil
	}
	for _, unloadedModule := range diff {
		if err := loadModule(expectedModules[unloadedModule]); err != nil {
			return err
		}
	}
	return nil
}
